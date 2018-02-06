# Visual tool to test ROCA vulnerable keys

![](https://i.imgur.com/3fb5Xje.png)


This tool is related to [ACM CCS 2017 conference paper #124 Return of the Coppersmith’s Attack: Practical Factorization of Widely Used RSA Moduli](https://crocs.fi.muni.cz/public/papers/rsa_ccs17).


Currently the tool supports the following key formats:

- X509 Certificate, DER encoded, one per file, `*.der`, `*.crt`
- X509 Certificate, PEM encoded, more per file, `*.pem`
- RSA PEM encoded private key, public key, more per file, `*.pem` (has to have correct header `-----BEGIN RSA...`)
- SSH public key, `*.pub`, starting with "ssh-rsa", one per line
- ASC encoded PGP key, `*.pgp`, `*.asc`. More per file, has to have correct header `-----BEGIN PGP...`
- APK android application, `*.apk`
- modulus that can be
    a) base64 encoded number, b) hex coded number, c) decimal coded number
- PKCS7 signature with user certificate

## Install with pip

Install the detector library + tool with `pip` (installs all dependencies):

```
pip install Detector
```

## Dependencies

It may be required to install additional dependencies so `pip` can install e.g. cryptography package.


Ubuntu:
```
sudo apt-get install python-pip python-dev python-tk build-essential libssl-dev libffi-dev swig M2crypto
```

## Usage

excute 'Detector' in terminal 


