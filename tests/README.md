# Generating certificates with cfssl

```bash
cat << EOF > /tmp/csr.ca.json 
{
    "CA": {
        "expiry": "87600h",
        "pathlen": 0
    },
    "CN": "test",
    "key": {
        "algo": "ecdsa",
        "size": 256
    },
    "names": [
        {
            "C":  "US",
            "L":  "San Francisco",
            "O":  "Internet Widgets, Inc.",
            "OU": "WWW",
            "ST": "California"
        }
    ]
}
EOF

cat << EOF > /tmp/csr.json 
{
    "hosts": [
        "localhost",
        "https://localhost",
        "https://127.0.0.1",
        "127.0.0.1"
    ],
    "key": {
        "algo": "ecdsa",
        "size": 256
    },
    "names": [
        {
            "C":  "US",
            "L":  "Dallas",
            "O":  "My Certificate",
            "OU": "WWW",
            "ST": "Texas"
        }
    ]
}
EOF

# IMPORTANT: we have also client auth in server profile because redis needs multipurpose certificates, otherwise even
# server side TLS doesn't work
cat << EOF > /tmp/config.json 
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "server": {
        "usages": ["signing", "key encipherment", "digital signature", "server auth", "client auth"],
        "expiry": "87600h"
      },
      "client": {
        "usages": ["signing", "digital signature", "client auth"],
        "expiry": "87600h"
      }
    }
  }
}
EOF

cfssl genkey -initca /tmp/csr.ca.json | cfssljson -bare ca
cfssl gencert -ca ca.pem -ca-key ca-key.pem -config /tmp/config.json -profile server /tmp/csr.json | cfssljson -bare
```