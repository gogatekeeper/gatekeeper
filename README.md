
# Gatekeeper

This repository is a work in progress and contains the source code for the Gatekeeper. You should be able to see what's being planned at our [milestones page](https://github.com/gogatekeeper/gatekeeper/milestones).

## Help and Documentation

* [Gatekeeper documentation](docs/user-guide.md)
* [Gatekeeper security issues](SECURITY.md)
* [Gatekeeper chat](https://discord.com/invite/zRqVXXTMCv)
* [Helm chart](https://github.com/gogatekeeper/helm-gogatekeeper)
* [Issue Tracker](https://github.com/gogatekeeper/gatekeeper/issues) - Issue tracker for bugs and feature requests

## Reporting an issue

If you believe you have discovered a defect in Gatekeeper please open an issue in our [Issue Tracker](https://github.com/gogatekeeper/gatekeeper/issues).
Please remember to provide a good summary, description as well as steps to reproduce the issue.

## Getting started

To run Gatekeeper, please refer to our [building and working with the code base](docs/building.md) guide. Alternatively, you can use the Docker image by running:

    docker run -it --rm quay.io/gogatekeeper/gatekeeper:1.3.9 \
      --listen 127.0.0.1:8080 \
      --upstream-url http://127.0.0.1:80 \
      --discovery-url https://keycloak.example.com/auth/realms/<REALM_NAME> \
      --client-id <CLIENT_ID>

For more details refer to the [Documentation](docs/user-guide.md).


### Verifying Download

Beside links to archives of binaries we provide also checksum file containing checksums
for archives. You can download file gatekeeper-checksum.txt, it contains sha512 checksums e.g.:

```
324b34ece86b6214f835ba9fd79e185864a9005f514458796c22c053de63f428235d2d2a04864065a49c090ad81d2daeb45546544fdd9531a8dea1a43145b8f0  gatekeeper_1.3.9_windows_amd64.zip
38759e75a94d130758cd26958bd9a66b261be8d58a6c7a0fc04845157649aaf628d22a115c95285b405f8e4d6afa8bd78ca8677d1304faf06db93a0cbbc831a6  gatekeeper_1.3.9_linux_amd64.tar.gz
f5322e41b3d78017191246bdd54f99e9b3dd8d5ff9d224e7e81b678a952c1d5aae125ea4c251928969b0a0ea0dc59724308c918993c8227f384f61896f58cbd0  gatekeeper_1.3.9_macOS_amd64.tar.gz
```

After you download archive of binary you can calculate it's checksum by using e.g. sha512sum Linux utility:

```
sha512sum /my/path/gatekeeper_1.3.9_linux_amd64.tar.gz
38759e75a94d130758cd26958bd9a66b261be8d58a6c7a0fc04845157649aaf628d22a115c95285b405f8e4d6afa8bd78ca8677d1304faf06db93a0cbbc831a6  gatekeeper_1.3.9_linux_amd64.tar.g
```

As you can see output of command is checksum, you can compare it with the one in gatekeeper-checksum.txt.

Additionally to verify gatekeeper-checksum.txt is valid we provide also signature of checksum file gatekeeper-checksum.txt.sig.

You can validate signature with these steps:

1. Download and save gpg public key:

```
cat > /tmp/gpg <<EOF
-----BEGIN PGP PUBLIC KEY BLOCK-----                                                                                                                                                                                                                                           

mQINBGA0GBoBEAC3Y6rwIhkDc+eXIyh+RlbLHkmCZw9rHz7TkMIoWC0LrZf1h5o0                                                                                                                                                                                                               
we/RXdGjRcRj1Pm3HCgsonjicHkOW4Dv2hN/oBbbHGDfcSGL+9H/6JiC3oZ95GGn                                                                                                                                                                                                               
fONJJWjz+tPq9kTh3Gtiu9apOb2fV2xk3eIlcrAoAWHf9yHz4pIiGHxEZX+nLEv5                                                                                                                                                                                                               
LoDDLaNe/AG4UO/ZF+3Bd/W9bsyi73JPBkoyJOtsuD/7v5YFZlloIMc4ND2lCRu9                                                                                                                                                                                                               
8IQ1M+K+3OoZriON6C55Jt4cFMfMgBA/WYIRHU/pVmAanx/imLNiwNDPLldKmNem                                                                                                                                                                                                               
sWgfrf7jyP2AHnLXrMgxFyqdTbtXhVnvcd82i/UA0IjoGzp34x/9U5B+YUMKJ5iu                                                                                                                                                                                                               
1Rv2lnWI6OPwB1fW5DawIW5sV+qvXVzTd8opUs1O/sF1+w77+aShA2NJc73PlS1+                                                                                                                                                                                                               
h9ENUwqcRpalUm7CGlOVA+wd8HZGkEbxRkvt50hopLr0X9YtqFVyShk/hsLVjykH                                                                                                                                                                                                               
Fr8RiKVgbqDMdV/bCDfb7xM/TlnxiF2+qu1DqdbO73hJRnOyOeMqeQjPnly0hnh6                                                                                                                                                                                                               
rF2XHr3F471w9F5LZA0kD3AwubUvMacYFJyAOJTHuf6nNjH27GLOotWupZ1y/MMA                                                                                                                                                                                                               
HL76TJIy7c7qjm8ZZ+wa13Ldc2MZhqPVurNFZPYILJWNFk/z/itnnRfklQARAQAB                                                                                                                                                                                                               
tDtnb2dhdGVrZWVwZXIgKGdvZ2F0ZWtlZXBlcikgPGdvZ2F0ZWtlZXBlckBnb2dh                                                                                                                                                                                                               
dGVrZWVwZXIuY29tPokCTgQTAQoAOBYhBMkDPWjiWZhznf2qCNoqrHlliwxzBQJg                                                                                                                                                                                                               
NBgaAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJENoqrHlliwxzPSMP/1Iy                                                                                                                                                                                                               
uZUpR7QKufq4yPNgrIOa6HjAO20t88jXa9VwSTj93EvpeeYUVcpQZ9Blc23q3RSR                                                                                                                                                                                                               
GnEnb/aRu+53OEIImC1T9u5nqqlV/ulWbog4y6sxq41QdRDL3uUsbWhmEwh3xFLj                                                                                                                                                                                                               
51qjz6WKrjxHi8BbgImkcN4ByVsZ5xvl2e0KYkABo9dWp9VvAtNHQbHyQWwSLBGl                                             
hTbvvFAbsDpDcZC/OcK6fZQxYMjoSurhnjqTtPyETYivon+QuPOimGbQKFgn+YEl          
YLyfMDuo6fpwS0XFRAe9zGp5EFcachzGG4UQCwUeT9qpHLo3joTkjbXsbA0hcX1y               
mZQXFMb+uJk3r5U+lqghBKJfei+ShrJ87nl7h9l9nb3mWuYCPloJjdhQ9k/d7lT7
X4i7Q0CTZpUJgJG/xjOa0WHBo0gOFPCV7P5ME5LinjVF2zfIg7dK2RIMiBlhqVz8                                                                
BYHfMbnVbPZc0pf940a1Zw1ZoDz9AoekhNBS0eB1AApUnaUMDUHPqulrCcAX3/2i     
9Fr6f3RqtRu2RtUpwo1wLhXfxxdPL46o8lQFHJy0n2N2tBKhb2HOgXV7YSaI7JA4
ttnp0H2ADbpJ6NW+wxzf3nSHHAc8t3XWsfmRF0DVe2e3v3CbN6D2DWQQT92CVWKt
GxjTVBnQ8fLfTqYKczU2UROXst0ZFt5gS9AVcrRYuQINBGA0GBoBEACaEbSD5s2v          
iAhD0Fvp6oS8Zrb7DbH2dmpJdVZ2DnIK3lden7vJPON8d3Fwc3lt7AgbK0QAN4Fh                                 
8sQM4E28onGR4j9l9d0Te7t0vjNBc9UZFLH5mY3e2Uy5OO1LDI3FG2nQ4Z7BB08N     
lXlR3kRQyyGMDF9g1NxeAFnYL/8/QB+DvaPYwBsZEJHbCUBalAaehGGmeCEW3/aw
/Pex46giPA+Dqpig8rh6wA/MovqGSx0km/xLHmQPGhh/T1w7aFC1bDTEZKvTGsJ3                                    
dBYtHYcaUrp94dGsxCPFraDqemSdrNe069gO/Fu+qCPFb0VzZh0BZEkxNXbmFQJs
CVthFgkmeAOKacHNqYepPj9RgDkdW5H9iN/UIoVm+TSY6X5FEruA7PA3uNPErHP4                   
fSAqMwVhG3V1rNdCHghONvFzSwlge1t5x0ci4Kei3JkOjGP87uGeuGPg1BS3msxn
Vfv2V6hKtZTBvWjOY9l2dlpxiFuLYuz7LJAl9LO15FG2TEJgt4ciYHJizlqKUyBI
JmZ/4ggGTVTlt9TSPumwLmaSfsuS5C7pVKb4sVwQArhHkTaoIEBBdPVKBfXqfsk3
zK+/m3Cbu/p+2uiYBFPhSj7npZGsaAfdVFwN99sR3bWV8O8CsY7IolQY4FEgZHcg
GTNRRHmsf6t7UaWqYvTO2Nsy4YDyVgLgQQARAQABiQI2BBgBCgAgFiEEyQM9aOJZ
mHOd/aoI2iqseWWLDHMFAmA0GBoCGwwACgkQ2iqseWWLDHNi5BAAkKwqRdginucS
piwAz8E1A9PCPcPAkuz5Ut89cTzoWecfsEcuunZRVBCy0QS0VQQljEcyvXJC49OJ
Qyvj42lXtLtGr4dr9ICtwMGmkVf5HCccFfwBExfEHNnc3RefAr1TkaParbb7Lspy
uTF17MIGqHBp+edPkK8hwLIYqu1r/R3gcXO+ptweEvDXO1rcSWg7OkzefMIkrBso
7tuju93CK28lAzTycTi6rnOcZZmFSTdHt9bdzrfxIHCtOLp1TOC7gGI5bvy4FRdS
OHcXygk/lHVHqklIqs23rqQjd4I5rd2j311nTFFMixEB+DQckQ1VahknsWc9+8p6
IdEM5adbmrdPYKiGiVERBrZG3xUQP48TNdXhAzL/6b5qYJf3Y66ThZHlrzkGrP4P
zWzYLneYiCtdvfmGmzW5neB/Mh+FbSfTWq3WTAfFapwsFOKjhkXXwEVEV3gR1HAd
8dSwBxyNfuBrQxHw9julzt7EBe4NpHBj2p1XqdNBRaZ5MfR6j84a+XLOPsmGHPJs
YI6HbpDuVj/V0nx/qQd2fdRtTDGcrhrGmJ6wGJcXlQ9z2ZcyO4W7zM230Yos6xud
rJQpPMfESrwVZzaOJWATXd+9Xq8ilYOcgUgq2I8Ja/lTiy5EaOVDDJVG1SfSekNq
UY4aXHYaaLMBc+zBnO1hIgSV0T6w8/Q=
=/W6g                                                                                                                                      
-----END PGP PUBLIC KEY BLOCK-----
EOF
```

2. Check fingerprint of public key, you should see **C9033D68E25998739DFDAA08DA2AAC79658B0C73** there:

```
cat /tmp/gpg|gpg --import-options show-only --import
pub   rsa4096 2021-02-22 [SC]
      C9033D68E25998739DFDAA08DA2AAC79658B0C73
uid                      gogatekeeper (gogatekeeper) <gogatekeeper@gogatekeeper.com>
sub   rsa4096 2021-02-22 [E]

```

3. Import gpg public key

```
cat /tmp/gpg | gpg --import
```

4. Verify signature

```
gpg --verify gatekeeper-checksum.txt.sig
```

### Writing Tests

To write tests refer to the [writing tests](docs/tests-development.md) guide.

## Contributing

Before contributing to Gatekeeper please read our [contributing guidelines](CONTRIBUTING.md).

## Other Keycloak Projects

* [Keycloak](https://github.com/keycloak/keycloak) - Keycloak Server and Java adapters
* [Keycloak Documentation](https://github.com/keycloak/keycloak-documentation) - Documentation for Keycloak
* [Keycloak QuickStarts](https://github.com/keycloak/keycloak-quickstarts) - QuickStarts for getting started with Keycloak

## License

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
