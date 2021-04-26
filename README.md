## tlsgencer a wrapper over openssl to generate test server certificates.

### Certificates can be used forr MongoDB Deployments, or other servers in general. 

### Generates CA Certs --signs--> IA Certs --signs--> Server Certs

### Usage:

- By supplying server name directly
```
./tlsgencer -server -host=localhost.com,myaws.com -cn=testserver

% ./tlsgencer -server -host=localhost.com,myaws.com -cn=testcert
Option is to generate server certs
List of serrvers:  [localhost.com myaws.com]
CN:  testcert

No CA exist to sign certificates, generating CA certs.......
Gerenrating Openssl Config.....

File Name: openssl-CA.cnf created successfully
Length: 1274 bytes written
 Generating CA key of length 4096

Generating RSA private key, 4096 bit long modulus
..................................++
..................................................................................................................................................++
e is 65537 (0x10001)

Gerenrating Openssl Config.....

File Name: openssl-IA.cnf created successfully
Length: 1270 bytes written
 Generating IA key of length 4096

Generating RSA private key, 4096 bit long modulus
...........................................................................................................++
.............++
e is 65537 (0x10001)


CA Cert generation was successful: tlsgencer-ca.crt 

IA Cert CSR generation was successful:

IA Cert generation was successful: tlsgencer-ia.crt

File Name: openssl-server.cnf created successfully
Length: 713 bytes written
 Generating server key of length 4096

Generating RSA private key, 4096 bit long modulus
.................................................++
..........................................++
e is 65537 (0x10001)


Server Cert CSR generation was successful:

Server Cert generation was successful: tlsgencer-server.crt

% openssl x509 -in tlsgencer-server.crt -noout -text 
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 15727668193963566886 (0xda43e6e4c6686726)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=IN, ST=New Delhi, L=New Delhi, O=MongoDB, OU=TSE, CN=tlsgencerCA
        Validity
            Not Before: Apr 26 05:24:43 2021 GMT
            Not After : Apr 26 05:24:43 2022 GMT
        Subject: C=IN, ST=New Delhi, L=New Delhi, O=MongoDB, OU=TSE, CN=testcert
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption

```
- By supplying a config file e.g. see server.json
```
./tlsgencer -server -config=server.json
```
- server.json format
```
{
    "CN": "Roshans-MacBook-Pro.local",
    "hosts": [
        "localhost",
        "Roshans-MacBook-Pro.local",
        "myaws.com"
    ],
    "IPs": [
        "127.0.0.1",
        "10.1.2.1"
    ],
    "key": {
        "algo": "rsa",
        "size": "4096"
    },
    "names": {
        "C": "IN",
        "ST": "DL",
        "L": "New Delhi",
        "O": "MongoDB",
        "OU": "TSE"
    }
}
```
