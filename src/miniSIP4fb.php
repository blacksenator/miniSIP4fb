<?php

namespace blacksenator\miniSIP4fb;

/**
 * This class provides functions for a minimalist softphone. Since the AVM 
 * FRITZ!Box does not provide the option to end an incoming call via API (SOAP), 
 * these functions represent a workaround. The headless softphone can accept and 
 * end an incoming call after successfully registering as a SIP client.
 * 
 * Some notes on the messages defined in Heredoc:
 * 1. After analyzing the responses from FRITZ!Box, all lines are ended with a
 *    [CR][LF]. Hence the "\r" at the end ("\n" is implicitly determined by
 *    Heredoc itself).
 * 2. This has the advantage, that any blank lines created by variables can be
 *    easily eliminated, because...
 * 3. a SIP message must always end with a blank line - and only there or 
 *    between the announced payload (if content length > 0)
 *
 * @author Volker Püschel <knuffy@anasco.de>
 * @copyright Volker Püschel 2025
 * @license MIT
 */
 
use blacksenator\sipSocket2fb\sipSocket2fb;

class miniSIP4fb
{  
    const DEVICE   = 'miniSIP4fb',
        BRANCHPRFX = 'z9hG4bK',
        METHODS    = ['INVITE', 'ACK', 'BYE', 'CANCEL'],
        EXPIRES    = 300,                       // default value in seconds
        LEADTIME   = 30;

    private $user,                              // IP-phone password
            $password,                          // IP-phone password
            $device,                            // IP-phone name (optional) 
            $serverIP,                          // SIP server (FRITZ!Box)
            $sipPort,                           // (5060)
            $sdpPort,
            $clientIP,                          // SIP client
            $sockets,
            $method = 'REGISTER',               // REGISTER = initial method
            $branch,
            $allow,
            $checkMethods = [],
            $tag,
            $callID,
            $sequence = 1,
            $branchSFX,
            $idSFX,
            $uUID,
            $received = [],                     // data received from server
            $realm = '',                        // credential from server 
            $nonce = '',                        // credential from server
            $body = '',                         // default für qop="auth-int"
            $response = null,
            $authorization = null,
            $sdpBody,
            $bodyLength,
            $expires = self::EXPIRES,
            $leadTime = self::LEADTIME,
            $registered = false,
            $nextRegistration,
            $responseTag;              

    public function __construct(string $user, string $password, array $param = []) 
    {
        $this->user = $user;
        $this->password = $password;
        $this->sockets = new sipSocket2fb($param);
        $this->setParameter($param);
        $this->clientIP = gethostbyname(php_uname('n'));
        $this->setBranch();
        $this->checkMethods = [...self::METHODS, $this->method];
        $this->setTag();
        $this->setCallID();
        $this->setUUID();
        // $this->setSDPBody() Explanation for the comment see below at function
    }

    /**
     * set parameters
     * overwriting default IP parameters and more
     * 
     * @param array $param
     * @return void
     */
    private function setParameter(array $param)
    {
        $this->serverIP = $param['remoteIP'] ?? $this->sockets::REMOTEHOST;
        $this->sipPort  = $param['cSIPPort'] ?? $this->sockets::SIP_PORT;
        $this->sdpPort  = $param['cSDPPort'] ?? $this->sockets::SDP_PORT;
        $this->device   = $param['device'] ?? self::DEVICE;
        $this->allow    = $param['allow'] ?? implode(', ', self::METHODS);
    }

    /**
     * set CSeq
     */
    private function setSequence(int $sequence)
    {
        $this->sequence = $sequence;
    }

    /**
     * set branch
     * 
     * @return void
     */
    private function setBranch()
    {
        $this->branch = self::BRANCHPRFX . substr(md5(uniqid('')), 0, 20);
    }

    /**
     * set the tag (outbound)
     */
    private function setTag()
    {
        $this->tag = rand(1000000000,9999999999);
    }

    /**
     * set the callID (outbound)
     * 
     * @return void 
     */
    private function setCallID()
    {
        $uid = str_split(strtoupper(md5(uniqid())), 4);
        $this->idSFX = $this->idSFX ?? $uid[5] . $uid[6] . $uid[7];
        $this->branchSFX = $this->branchSFX ?? strtolower($this->idSFX);
        $idBody = $uid[0] . $uid[1] . '-'. $uid[2] . '-'. $uid[3] . '-'. $uid[4];
        $this->callID = $idBody . '-' . $this->idSFX . '@' . $this->clientIP;
    }

    /**
     * set the UUID (outbound)
     * 
     * @return void
     */
    private function setUUID()
    {
        $uid = str_split(strtoupper(md5(uniqid())), 4);
        $this->uUID = $uid[0] . $uid[1] . '-'. $uid[2] . '-'. $uid[3] . '-'. $uid[4] . '-' . $uid[5] . $uid[6] . $uid[7];
    }

    /**
     * set response hash
     * fits for REGISTER and SUBSCRIBE, but recently only REGISTER is used 
     * 
     * @param string $method
     * @return void
     */
    private function setResponseHash($method)
    {
        $this->realm = $this->received['realm'];
        $this->nonce = $this->received['nonce'];
        $a1Hash = md5($this->user . ':'. $this->realm . ':' . $this->password);
        if (isset($this->received['qop']) &&
            $this->received['qop'] === 'auth-int') {
            $a2Hash = md5($method . ':sip:' . $this->serverIP . ':' . $this->body);
            $cnonce = md5(time());
            $auth = $a1Hash . ':' . $this->nonce . ':00000001:' . $cnonce . ':auth:' . $a2Hash;
        } else {                                                    // default
            $a2Hash = md5($method . ':sip:' . $this->serverIP);
            $auth = $a1Hash . ':' . $this->nonce . ':' . $a2Hash;
        }
        $this->response = md5($auth);
    }

    /** 
     * Set authorization after first attemp and receiving initial credentialials
     * from server (nonce & realm)
     * 
     * @param string $method
     * @return void
     */
    private function setAuthorization(string $method)
    {
        if (isset($this->received['nonce']) && isset($this->received['realm'])) {
            $this->setResponseHash($method);
            $this->authorization = <<<AUTHORIZATION
Authorization: Digest username="$this->user", realm="$this->realm", nonce="$this->nonce", uri="sip:$this->serverIP", response="$this->response", algorithm=MD5\r
AUTHORIZATION;
        }
    }

    /** 
     * Compose a request message to register on server 
     * 
     * @return string
     */ 
    private function setRegistration()
    {
        $message = <<<REGISTRATION
REGISTER sip:$this->serverIP SIP/2.0\r
Via: SIP/2.0/UDP $this->clientIP:$this->sipPort;branch={$this->branch}{$this->branchSFX};rport\r
From: "$this->device" <sip:$this->user@$this->serverIP>;tag=$this->tag\r
To: "$this->device" <sip:$this->user@$this->serverIP>\r
Call-ID: $this->callID\r
CSeq: $this->sequence REGISTER\r
Contact: <sip:$this->user@$this->clientIP>;+sip.instance="<urn:uuid:$this->uUID>"\r
{$this->authorization}
Allow: $this->allow\r
Max-Forwards: 70\r
Allow-Events: org.3gpp.nwinitdereg\r
User-Agent: $this->device\r
Supported: replaces, from-change\r
Expires: $this->expires\r
Content-Length: 0\r
\r\n
REGISTRATION;

        return str_replace("\n\n", "\n", $message);
    }

    /**
     * Set response tag
     * 
     * @return void
     */
    private function setResponseTag()
    {
        $this->responseTag = uniqid();
    }

    /**
     * Compose a minimal SDP (Session Description Protocol) body as a generic
     * payload
     * 
     * Note:
     * Since the server accepts a 200 OK after INVITE even without SDP payload, 
     * this part is not needed yet, but remains in the code for illustration 
     * purposes or as a basis for future developments.
     * 
     * @return void
     */
    private function setSDPBody()
    {
        $sessionID = rand(1000000000, 9999999999);
        $this->sdpBody = <<<SDPBODY
v=0\r
o=- $sessionID 1 IN IP4 $this->clientIP\r
s=-\r
c=IN IP4 $this->clientIP\r
t=0 0\r
m=audio $this->sdpPort RTP/AVP 0\r
a=rtpmap:0 PCMU/8000\r
a=sendrecv\r
\r\n
SDPBODY;
        $this->bodyLength = strlen($this->sdpBody);
    }

    /**
     * Compose the response messages according to an INVITE from the SIP server
     * (FRITZ!Box). There are three messages as responses in use:
     * 100 Trying,
     * 180 Ringing and
     * 200 OK.
     * Trying and Ringing are provisional responses.
     * 
     * @param string $response
     * @return string
     */
    private function setInviteResponse(string $response)
    {
        $to = $this->received['To'];
        $contact = "Contact: <sip:$this->user@$this->clientIP>\r\n";
        $supported = "Supported: replaces, from-change, 100rel\r\n";;
        if ($response === 'Trying') {
            $code = '100';
            $contact = '';
            $supported = '';
        } elseif ($response === 'Ringing') {
            $code = '180';
            $to .= ';tag=' . $this->responseTag;
        } elseif ($response === 'OK') {
            $code = '200';
            $to .= ';tag=' . $this->responseTag;
        }
        $message = <<<INVITERESPONSE
SIP/2.0 $code $response\r
Via: {$this->received['Via']}\r
From: {$this->received['From']}\r
To: $to\r
Call-ID: {$this->received['Call-ID']}\r
CSeq: $this->sequence INVITE\r
{$contact}
Allow: $this->allow\r
{$supported}
Server: $this->device\r
Content-Length: 0\r
\r\n
INVITERESPONSE;
        $message = str_replace(["\n\n"], "\n", $message);
        /* see setSDPBody()
        if ($response === 'OK') {
            $message .= $this->sdpBody;
        } */

        return $message;
    }

    /**
     * Compose the hang up request
     * 
     * @return string
     */
    private function setHangUpRequest()
    {
        $this->setBranch();

        return <<<HANGUP
BYE sip:{$this->received['contact sip']} SIP/2.0\r
Via: SIP/2.0/UDP $this->clientIP:$this->sipPort;branch={$this->branch}{$this->idSFX};rport\r
From: {$this->received['To']}\r
To: {$this->received['From']}\r
Call-ID: {$this->received['Call-ID']}\r
CSeq: $this->sequence BYE\r
Contact: {$this->received['Contact']}\r
Max-Forwards: 70\r
User-Agent: $this->device\r
Content-Length: 0\r
\r\n
HANGUP;
    }

    /**
     * Parse inbound messages from SIP server
     * 
     * @param string $message
     * @return void
     */
    private function parseMessage(string $message)
    {
        $this->received = [];                                   // clear array
        if (!empty($message)) {
            $msg = preg_replace(['/^\s*[\r\n]/m', '/\\r\n$/'], '', $message);
            $lines = explode("\r\n", $msg);
            $about = explode(' ', $lines[0]);
            // head
            if ($about[0] === 'SIP/2.0' && ctype_digit($about[1])) {
                $this->received['Response-Code'] = $about[1];   // response code
            } elseif (in_array($about[0], $this->checkMethods) ) {
                $this->received['Method'] = $about[0];
            } elseif (in_array($about[1], $this->checkMethods) ) {
                $this->received['Method'] = $about[1];
            }
            $lines = array_slice($lines, 1);    // skip to second item (line)
            // attributes
            foreach ($lines as $line) {
                [$key, $value] = explode(': ', $line);
                $this->received[$key] = $value;
                if ($key === 'Content-Length') { 
                    break;                          // we don´t need the payload
                }
            }
            if (count($this->received)) {
                [$this->received['CSeq'], $this->received['Method']] = explode(' ', $this->received['CSeq']);
                if ($this->received['Content-Length'] >= 1) {               // default 0
                    $this->received['Content-Length'] = trim($this->received['Content-Length']);
                    $this->received['content'] = substr($message, $this->received['Content-Length'] * -1 );
                }
                // parameter
                if (isset($this->received['Via']) &&
                    preg_match('/rport=(\d+)/', $this->received['Via'], $matches)) {
                    $this->received['rport'] = $matches[1];
                }
                if (isset($this->received['Contact'])) {
                    if (preg_match('/sip:[^>]+/', $this->received['Contact'], $matches)) {
                        $this->received['contact sip'] = $matches[0];
                    }
                    if (preg_match('/expires=(\d+)/', $this->received['Contact'], $matches)) {
                        $this->received['expires'] = $matches[1];
                        $this->expires = $this->received['expires'];
                    }
                }
                if (isset($this->received['From'])) {
                    if (preg_match('/tag=(\d+)/', $this->received['From'], $matches)) {
                        $this->received['tag'] = $matches[1];
                    }
                    if (preg_match('/"([^"]*)"/', $this->received['From'], $matches)) {
                        $this->received['name'] = $matches[1];
                    }
                    if (preg_match('/sip:([^"]*)@/', $this->received['From'], $matches)) {
                        $this->received['number'] = $matches[1];
                    }
                }
                if (isset($this->received['WWW-Authenticate'])) {
                    if (preg_match('/realm="([^"]+)"/', $this->received['WWW-Authenticate'], $matches)) {
                        $this->received['realm'] = $matches[1];
                    }
                    if (preg_match('/nonce="([^"]+)"/', $this->received['WWW-Authenticate'], $matches)) {
                        $this->received['nonce'] = $matches[1];
                    }
                    if (preg_match('/qop="([^"]+)"/', $this->received['WWW-Authenticate'], $matches)) {
                        $this->received['qop'] = $matches[1];
                    }
                }
            }        
        }
    }

    /**
     * Compare identificators
     * 
     * 
     * 
     * @return bool
     */
    private function compareIdentificators()
    {
        if (count($this->received)) {
            if ($this->received['CSeq'] == $this->sequence &&
                $this->received['Method'] == $this->method &&
                $this->received['Call-ID'] == $this->callID &&
                $this->received['tag'] == $this->tag) {
                return true;
            }
        }

        return false;
    }

    /**
     * send request
     * 
     * @param string $message
     * @return bool
     */
    private function sendRequest(string $message)
    {
        $response = $this->sockets->sendRequest($message);
        if ($response !== false) {
            $this->parseMessage($response);
            return true;
        }

        return false;
    }
    
    /**
     * send a control message (request) to the SIP server. Either to register 
     * the SIP client or to teminate a picked up call.
     * 
     * @param string $method
     * @return void
     */
    public function sendControlRequest(string $method)
    {
        $maxAttemps = 10;
        $attemp = 0;
        isset($this->authorization) && $this->authorization = null;
        do {
            $this->setBranch();
            if ($method === 'REGISTER') {
                $this->setAuthorization($method);
                $message = $this->setRegistration();
            } elseif ($method === 'BYE') {
                $message = $this->setHangUpRequest();
            } else {    // in case someone does not use the designated methods
                $message = '';
                $attemp = $maxAttemps;
            }
            if ($this->sendRequest($message)) {
                $this->sequence = $this->received['CSeq'] + 1;
            }
            $attemp++;
        } while ($this->received['Response-Code'] !== '200' &&
                $attemp < $maxAttemps &&
                !$this->compareIdentificators());
        if ($method === 'REGISTER' &&               // successfully registered
            $this->received['Response-Code'] === '200') {
            $this->nextRegistration = time() + $this->expires - $this->leadTime;
            $this->registered = true;
        }
    }

    /**
     * receives and parse a resquest from SIP server
     * 
     * @return bool
     */
    private function receiveRequest()
    {
        if (($request = $this->sockets->receiveRequest()) !== false) {
            $this->parseMessage($request['message']);
            $this->received['peer'] = $request['peer'];
            return true;
        }

        return false;
    }

    /**
     * Sends a response to the server upon a request
     * 
     * @param string $response
     * @return bool
     */
    private function sendResponse(string $response)
    {
        return $this->sockets->sendResponse($response);
    }

    /**
     * closes the open socket(s)
     * 
     * @return void
     */
    public function closeSocket()
    {
        $this->sockets->closeSocket();
    }

    /**
     * Returns the the number of an inbound call (RING) the SIP client is 
     * invíted for or false 
     * 
     * @param bool $silent
     * @return string|false
     */
    public function perceiveCall(bool $silent = true)
    {
        $number = '';
        if ($this->registered &&
            $this->receiveRequest() &&
            array_key_exists('Method', $this->received) &&
            $this->received['Method'] === 'INVITE')  {
            $this->setSequence($this->received['CSeq']);
            if ($this->sendResponse($this->setInviteResponse('Trying'))) {
                $number = $this->received['number'];
                $this->setResponseTag();                // setting an new tag
                if ($silent && $this->sendResponse($this->setInviteResponse('Ringing'))) {
                    $number = $this->received['number'];
                }
                return $number; 
            }
        }

        return false;
    }

    /**
     * Accepts an incoming call (RING) from a designated number
     * 
     * @param string $number
     * @return bool
     */
    public function pickUpCall($number)
    {
        if ($number == $this->received['number'] &&
            $this->sendResponse($this->setInviteResponse('OK'))) {
            if ($this->receiveRequest() && 
                array_key_exists('Method', $this->received) && 
                $this->received['Method'] === 'ACK') {
                return true;
            }
        }
    
        return false;
    }

    /**
     * terminates an inbound call (RING) from a designated number
     * 
     * @param string $number
     * @return bool
     */
    public function hangUp($number)
    {
        if ($number == $this->received['number']) {
            $this->setSequence($this->received['CSeq'] + 1);
            if ($this->sendControlRequest('BYE')) {
                return true;
            }
        }

        return false;
    }

    /**
     * 
     */
    public function refreshRegistration()
    {
        if (time() >= $this->nextRegistration) {
            $this->sendControlRequest('REGISTER');
        }
    }
}
