# A headless IP phone for AVM FRITZ!Box

## Purpose

This library provides a class for the limited use of SIP under PHP. With **miniSIP4fb**, a simple headless softphone can be operated as a client on a FRITZ!Box, with which primarily only an incoming call can be terminated. Because the AVM FRITZ!Box does not provide the option to end an incoming call via an API (e.g. with a [SOAP action][soap]), these functions represent a workaround.
In combination with the manageable number of easy-to-use functions, other use cases are also conceivable, e.g. for controlling actuators through a call. Extensions may be necessary for this.

I found some libraries for using SIP in PHP, but they followed a different functional approach, were in my opinion too complicated to use or had too much code for the intended purpose.

This software was created as an experiment. I wanted to test whether a virtual softphone (headless SIP client) could be used to accept and end incoming calls as easily as possible. Of course, the software has become more extensive than originally intended - also in order to cover as many eventualities as possible - even for this limited purpose.

## Requirements

* PHP 8.2 or higher
* Composer (follow the installation guide at [https://getcomposer.org/download/][composer])
* an IP phone configured on the FRITZ!Box

## Installation

You can install it through Composer:

```js
"require": {
    "blacksenator/mini-sip4fb": "^1.0"
},
```

or

```console
git clone https://github.com/blacksenator/miniSIP4fb.git
```

## Precondition

Of course, this software only works if a corresponding IP telephone has been defined on the FRITZ!Box beforehand. To do this, follow the [AVM instructions][AVM] in point **3**.
The following comments on this:

* 3.5 The name here (3.) is just a label. However, you can also transfer this to the softphone miniSIP4fb analogously using the [`'device'` parameter](#parameter), for example. But this is not necessary for the function
* 3.7 Remember the password well (or better yet, copy it). You will not be able to access it later, but you must pass it when instantiating miniSIP4fb. Of course, you can change the password of this device if you forget it
* 3.8 It doesn't matter which number you choose here. The software in its current state does not make calls
* 3.9 Here you should select all the phone numbers used so that miniSIP4fb receives an INVITE for every call - regardless of the number.
* There is no need to activate the registration from the Internet. Apart from that, AVM explicitly advises against this

## Usage

### Example

Below is a simple example how to use this class in your coding. Conveniently, you only need to enter the username and password of the IP telephone. This can be done in plain text, as this software can only be used within your FRITZ!Box home network. After setting up the IP phone on the FRITZ!Box you need to know these two credentials.

```PHP
<?PHP

require_once './src/miniSIP4fb.php';
require_once './src/sipSocket2fb.php';

use blacksenator\miniSIP4fb\miniSIP4fb;

$softPhone = new miniSIP4fb('name', 'password');
$softPhone->registerPhone();                            // initial Registration
while (true) {
    $softPhone->refreshRegistration();
    // the FRITZ!Box sets an expiration of 300 sec.
    if (!$number = $softPhone->perceiveCall()) {
        continue;
    }
    // this is the part where you decide whether the incoming call should be terminated
    if ($number !== $should_be_terminated) {
        continue;
    }
    // miniSIP4fb tries to accept the call
    if (!$softPhone->pickUpCall($number)) {
        continue;
    }
    // miniSIP4fb was able to answer the call; no other phone rings anymore - if it even rang anywhere else
    if ($softPhone->hangUp($number)) {
        echo "Connection with $number terminated\r\n";
    }
}
$softPhone->closeSocket();

```

Of course, the period of time between recognizing the INVITE from the FRITZ!Box and its final OK after the BYE (hang up) depends on the test steps in between and the hardware. In the example above, this takes a fraction of a second.

### Parameter

The transfer of the IP phone name and password when instantiating the class object is self-evident. To give the user more flexibility, a parameter array can optionally be passed:

```console
miniSIP4fb(string $user, string $password, ?array $param)
```

The  `$param` array can pass the following values:

key        |description                                      |default
-----------|-------------------------------------------------|-
'remoteIP' |FRITZ!Box IP or hostname                         |'fritz.box'
'cSIPPort' |client SIP port (your device)                    |'5060'
'cSDPPort' |client SDP port (not in use)                     |'5062'
'rSIPPort' |remote SIP port (FRITZ!Box)                      |'5060'
'localHost'|your device                                      |'0.0.0.0'
'timeOut'  |waiting for response or status changes (requests)|5 (sec)
'timeZone' |your local time zone                             |'Europe/Berlin'
'device'   |label of your softphone in SIP messages          |'miniSIP4fb'
'timeZone' |your local time zone                             |'Europe/Berlin'
'allow'    |supported methods                                |['INVITE', 'ACK', 'BYE', 'CANCEL']
'logFile'  |path and filename                                |'' (no logging)

## Demarcation

In my repositories you can find various solutions that use different FRITZ!Box interfaces:

* The [fbcallrouter][fbcallmonitor] program uses the call monitor interface
* The [fritzsoap][fritzsoap] library provides the functions for the SOAP actions

This library will be integrated into the [fbcallrouter][fbcallmonitor] in order to close the gap [described there][fbcmimprove], namely that incoming spam calls from previously unknown numbers could not be terminated immediately. Unlike the call monitor interface (Port 1012) previously used in it , miniSIP4fb cannot of course perceive outgoing calls from other connected telephones. It cannot replace the call monitor in this manner.

The [fritzsoap][fritzsoap] library already used in fbcallmonitor, on the other hand, provides various actions in the x_voip service (e.g. **X_AVM-DE_GetClient...**), with which, for example, configuration data for connected (IP) telephones can be retrieved. Or, even more interesting, an IP telephone can be set with **X_AVM-DE_SetClient...**. None of this has been used here yet.

## Feedback

If you enjoy this software, then I would be happy to receive your feedback, also in the form of user comments and descriptions of your experiences, e.g. in the IP Phone Forum. This puts the user community on a broader basis and their experiences and functional ideas can be incorporated into further development. In the end, these features will benefit everyone.

## Improvements

As already indicated in [demarcation](#demarcation), it would be conceivable to use one of the SOAP actions **X_AVM-DE_SetClient...** from the **x_voip** service to avoid the software user having to manually set up the corresponding IP telephone on the FRITZ!Box beforehand. This would rule out any possible transmission errors in the credentials.

## Gratitude

My special thanks go to Heiko Sommerfeldt, whose softphone solution [PhonerLite][phonerlite] with its protocol recording was an invaluable source of knowledge for me - in addition to his tips when I didn't understand at all why the FRITZ!Box wasn't responding to me.

## Disclaimer

FRITZ!Box, FRITZ!Repeater, FRITZ!OS are trademarks of AVM. This software is in no way affiliated with AVM and only uses the interfaces published by them.

## License

This script is released under MIT license.

## Author

Copyright (c) 2025 Volker Püschel

[phonerlite]: http://www.phonerlite.de/index_de
[soap]: https://github.com/blacksenator/fritzsoap?tab=readme-ov-file#wishes
[AVM]: https://en.avm.de/service/knowledge-base/dok/FRITZ-Box-7590/42_Registering-an-IP-telephone-with-the-FRITZ-Box-and-setting-it-up/
[fbcallmonitor]: https://github.com/blacksenator/fbcallrouter/blob/master/README.md
[fritzsoap]: https://github.com/blacksenator/fritzsoap/blob/master/README.md
[fbcmimprove]: https://github.com/blacksenator/fbcallrouter/blob/master/README.md#improvements
[composer]: https://getcomposer.org/download/