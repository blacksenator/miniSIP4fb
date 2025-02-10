<?php

namespace blacksenator\miniSIP4fb;

/**
 * This class provides socket functions to communicate from and to SIP Ports on  
 * a FRITZ!Box
 *
 * @author Volker Püschel <knuffy@anasco.de>
 * @copyright Volker Püschel 2025
 * @license MIT
 */

class sipSocket2fb
{  
    const REMOTEHOST = 'fritz.box',
        SIP_PORT   = '5060',
        SDP_PORT   = '5062',                                // not in use
        LOCALHOST  = '0.0.0.0',                             // e.g '127.0.0.1'
        TIMEZONE   = 'Europe/Berlin';

    private $remoteIP,                      // fritz.box OR e.g. 192.178.168.1
            $localHost,
            $clientSIPPort,
            $remoteSIPPort,
            $clientSocket,          // on SIP client side to send requests    
            $serverSocket,          // on SIP client side to receive requests
            $peer,
            $timeOut,
            $lastMessage,
            $timeZone,
            $logFile;

    public function __construct(array $param = [])
    {
        $this->setParameter($param);
        date_default_timezone_set($this->timeZone);
    }

    /**
     * Initializing program parameters with defaults if not otherwise determined
     * 
     * @param array $param
     * @return void
     */
    private function setParameter(array $param)
    {
        $this->remoteIP = $param['remoteIP'] ?? self::REMOTEHOST;
        $this->clientSIPPort = $param['cSIPPort'] ?? self::SIP_PORT;
        $this->remoteSIPPort = $param['rSIPPort'] ?? self::SIP_PORT;
        $this->localHost = $param['localHost'] ?? self::LOCALHOST;
        $this->timeOut = $param['timeOut'] ?? 5;
        $this->timeZone = $param['timeZone'] ?? self::TIMEZONE;
        $this->logFile = $param['logFile'] ?? null;
    }

    /**
     * Geting timestamp
     * The "v" parameter doesn't work for me, even though the PHP version (8.*)
     * should be able to deliver milliseconds 
     * 
     * @return string
     */
    private function getTimeStamp()
    {
        $microtime = microtime(true);
        $seconds = floor($microtime);
        $microseconds = round(($microtime - $seconds) * 1000);  // hundredths of a second

        return date('d.m.Y H:i:s', $seconds) . ',' . str_pad($microseconds, 3, '0', STR_PAD_LEFT);
    }

    /**
     * Creates a UDP connection to the SIP server (FRITZ!Box)
     * 
     * @return bool
     */
    private function getClientSocket()
    {
        $address = 'udp://' . $this->remoteIP . ':' . $this->remoteSIPPort;
        if (!$this->clientSocket = stream_socket_client($address, $errno, $errstr, STREAM_CLIENT_CONNECT)) {
            $this->log("{$this->getTimeStamp()} Error creating UDP server: $errstr ($errno)");
            return false;
        }

        return true;
    }

    /**
     * Sends a message as a UDP client and receives the response
     * 
     * @param string $message
     * @param int $maxRetries
     * @return string|bool
     */
    public function sendRequest(string $request, int $maxRetries = 3)
    {
        for ($attempt = 1; $attempt <= $maxRetries; $attempt++) {
            if (!$this->getClientSocket()) {
                continue;
            }
            fwrite($this->clientSocket, $request);
            $this->log("{$this->getTimeStamp()} UDP client started. Request sendto {$this->remoteIP}:{$this->remoteSIPPort}:\r\n$request");
            stream_set_timeout($this->clientSocket, $this->timeOut);
            $response = fread($this->clientSocket, 2048);
            $info = stream_get_meta_data($this->clientSocket);
            $this->closeSocket($this->clientSocket);
            if ($info['timed_out']) {
                $this->log("{$this->getTimeStamp()} No response from the server within {$this->timeOut} seconds");
                continue;
            }
            if ($response !== false) {
                $this->log("{$this->getTimeStamp()} Received response from server:\r\n$response");
                return $response;
            }
        }
        $this->log("{$this->getTimeStamp()} Server not reachable. Aborted after $maxRetries attempts");

        return false;
    }

    /**
     * Starts the UDP socket on the SIP client to receive messages
     * 
     * @return bool
     */
    private function getServerSocket()
    {
        $address = 'udp://' . $this->localHost . ':' . $this->clientSIPPort;
        if (!$this->serverSocket = stream_socket_server($address, $errno, $errstr, STREAM_SERVER_BIND)) {
            $this->log("{$this->getTimeStamp()} Error creating UDP server: $errstr ($errno)");
            return false;
        }
        $this->lastMessage = '';
        $this->log("{$this->getTimeStamp()} UDP server started and listening on port {$this->clientSIPPort}...");

        return true;
    }

    /**
     * Returns true if socket is alive and message is received
     * 
     * @param array $sockets
     * @return bool
     */
    private function getSocketStatus()
    {
        if (!is_resource($this->serverSocket)) {
            $this->getserverSocket();
        }
        $read = [$this->serverSocket];
        $write = null;
        $except = null;
        $changedSockets = stream_select($read, $write, $except, $this->timeOut);
        if ($changedSockets === false) {
            $this->log("{$this->getTimeStamp()} Error in stream_select");
            return false;
        } elseif ($changedSockets === 0) {
            // $this->log("{$this->getTimeStamp()} No request received in the last $this->timeOut seconds");
            return false;
        } else {
            return true;
        }
    }    

    /**
     * Receives incoming requests
     * This function should be integrated into a permanent program loop, which
     * exists during program runtime:
     *     $socket = $instance->getServerSocket();
     *     while (true) {
     *         $request = $instance->receiveRequest();
     *         ...
     *         do stuff
     *         ...
     *     }
     *     $instance->closeSocket($socket);
     * 
     * @return array|false
     */
    public function receiveRequest()
    {
        if ($this->getSocketStatus()) {
            if ($request = stream_socket_recvfrom($this->serverSocket, 2048, 0, $peer)) {
                if ($this->lastMessage !== $request) {  // only non-repetitive messages
                    $this->lastMessage = $request;
                    $this->log("{$this->getTimeStamp()} Request received from $peer:\r\n{$request}");
                }
                $this->peer = $peer;
                return ['message' => $request, 'peer' => $peer];
            } else {
                $this->log("{$this->getTimeStamp()} Error receiving request");
                return false;
            }
        }

        return false;
    }

    /**
     * Sends a response to the server
     * 
     * @param string $response
     * @return bool
     */
    public function sendResponse(string $response)
    {
        if (stream_socket_sendto($this->serverSocket, $response, 0, $this->peer) === false) {
            $this->log("{$this->getTimeStamp()} Error sending response to $this->peer");
            return false;
        } else {
            $this->log("{$this->getTimeStamp()} Response sent to $this->peer:\r\n$response");
            return true;
        }
    }

    /**
     * Closes a socket - either server or client
     * It is ensured that the references are removed
     * 
     * @param resource $socket
     * @return void
     */
    public function closeSocket(&$socket = null)
    {
        if ($socket === null) {
            $socket = &$this->serverSocket;
        }
        if (is_resource($socket)) {
            fclose($socket);
            $socket = null;
        }
    }

    /**
     * Schreibt eine Nachricht in die Log-Datei, falls eine angegeben wurde.
     */
    private function log($message)
    {
        echo $message . PHP_EOL;
        if ($this->logFile) {
            file_put_contents($this->logFile, $message . PHP_EOL . PHP_EOL, FILE_APPEND);
        }
    }
}
