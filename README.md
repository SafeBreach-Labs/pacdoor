# Pacdoor

Pacdoor is a proof-of-concept JavaScript malware implemented as a Proxy Auto-Configuration (PAC) File. Pacdoor includes a 2-way communication channel, ability to exfiltrate HTTPS URLs, disable access to cherry-picked URLs etc.

It was released as part of the [Crippling HTTPS with Unholy PAC](https://www.blackhat.com/us-16/briefings.html#crippling-https-with-unholy-pac) talk given at BlackHat USA 2016 conference by Itzik Kotler and Amit Klein from [SafeBreach Labs](http://www.safebreach.com).

Slides are availble [here](https://www.blackhat.com/docs/us-16/materials/us-16-Kotler-Crippling-HTTPS-With-Unholy-PAC.pdf)

### Version
0.1.0

### Installation

Pacdoor requires [Python](https://python.org/) 2.7.x to run.

```sh
$ git clone https://github.com/SafeBreach-Labs/pacdoor.git
$ cd pacdoor
$ cd server
$ pip install -r requirements.txt
```

License
----

BSD 3-Clause
