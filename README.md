## tlsgencer a wrapper over openssl to generate test server certificates.

### Certificates can be used forr MongoDB Deployments, or other servers in general. 

### Generates CA Certs --signs--> IA Certs --signs--> Server Certs

### Usage:

- By supplying server name directly
```
./tlsgencer -server -host=localhost.com,testcert.test -cn=testserver
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
