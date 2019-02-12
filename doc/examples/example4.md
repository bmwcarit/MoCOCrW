Working with X509 certificates {#example4}
=============================

Certificate Loading and Verification
====================================
\code{.cpp}
const std::string rootPemString{R"(-----BEGIN CERTIFICATE-----
MIIFrDCCA5SgAwIBAgIJALlSpthVgAJEMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlhMQ8wDQYDVQQHDAZNdW5pY2gxDDAKBgNV
BAoMA0JNVzEPMA0GA1UECwwGQ2FyIElUMRIwEAYDVQQDDAlSb290IENBIDEwHhcN
MTcwMzI3MTI0NzExWhcNNDQwODEyMTI0NzExWjBjMQswCQYDVQQGEwJERTEQMA4G
A1UECAwHQmF2YXJpYTEPMA0GA1UEBwwGTXVuaWNoMQwwCgYDVQQKDANCTVcxDzAN
BgNVBAsMBkNhciBJVDESMBAGA1UEAwwJUm9vdCBDQSAxMIICIjANBgkqhkiG9w0B
AQEFAAOCAg8AMIICCgKCAgEAsC0O8CrynKompx7eO4+O6lavkbvfV/foNbnQ4PzI
hgr41bgB08eRsZIsesq1Btf8gt3771Qg0Phwu4KisHQGoiaJ4e/6mzQ2uRwUvihk
2KPCYBEkfT3YzY4/Te3QJy6afViW3kHk61hFN/smOhmQ6zJi57+Lm8QcA3ru1sK1
mdzmJl3HBLyAEd47kOejGWaUUEc9wlL37gicGBjgCZuoH2qnqDepuOQ0UwJjX/9l
Sp0n9CEtgcJFBBFZFgkq4XgKYQgOeb+qBPCxBCDJ/0T2zV8aP+ECD2DLZFR3DVAw
6OHTInOSnu3NUyw81TXSp0aF+X7OqWvT4ccMG0K10u60C3Ji4f12YAtyEngKiPZi
156g91DahdhR9up6FzQOp5x36XGLWsF4lWb2NA7TnVI8Jsm2p3B12qyN9GjQq1bk
3QGPEJFXIlB49jZsxdXnBQ8HnYFVtCEFYH8FtJiS7UcTDcfvNQpZvhNkbN9/tULG
Ch6tdFupTlH+x9eUjdqVWSGboltppWrU+We0nOTEr4J1rdsn9qYz/0KreQYQA3ZU
0o0eF6TrWBTJbJS67uTWemTkBEu9W7KOGpxI7eMKgmVaWownWDyCtLAKUBz8Nm6d
I3vDz2vo4LRV2YBN4d5TB6pes+/QOqdAbhBfe7LlOWovfbi7cSvYruqUhXsIP1vx
jisCAwEAAaNjMGEwHQYDVR0OBBYEFNMUo4azb3BwlBom1iA40BHPp4qyMB8GA1Ud
IwQYMBaAFNMUo4azb3BwlBom1iA40BHPp4qyMA8GA1UdEwEB/wQFMAMBAf8wDgYD
VR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQB8WbMd9sdpgPQ7PhWpeLJG
aH1xfkyZVGFEJ8iCwBgJrxHX7nqaESU0YM7Zb0RKYr8P65oclFxQlgvK/6ytKerH
2VO4TojKunHGcIn8XHnHPfvhoHoM9Ja89nsA9YdO/GnFEleKL3o0wZCGl46BvLAz
I5yGzafr0rd7aPIq/NQfSJsLvghP9BweJHg9MtE1mIYjBl9DShj0aUyfC56AbgTY
dsa4//d9ky3Dwrms+9vIvFfJEV7fC7RV3BMch52/o2gumVTJO3FX0S+B21fY6mdM
2yKSG3cjAd+iXuPqTp8GlvYJxkIWu0arepWBtw25ksDNACK+xEQhjZYMWkzTp3Nn
D/spRuPXKrJYWJVjju4kLIhgd2HR6Udhyfgh1SmleJwxX1yFNMdLp2tg9rSMtjNu
k90wEvaulMhE3PzvPk9HUeqvO+bVGxkIPEMi1XIsJmPupCaxC22qdSr3HU0Q2eKX
da6CF7q8sTp6+4GIN9sMfRGCEApYC5Pu08sQHnognT3h7P9mt7I8oCqlcZhzv9Jf
39/yoKbYT15/jb6Qk1SMxEEBZhMqAELf5OBkSl6KXxvw28P6moUpiG7pMQ8kJGYr
0aGibnSFz2zLE9RZ3wvdtkhjJdVYEkHryGUGdoufQXK+AKxo6E6Qp5kzZtQw8WHe
8vOTQDML0ZrwnQAlV9LZHQ==
-----END CERTIFICATE-----)"
};

const std::string intPemString{R"(-----BEGIN CERTIFICATE-----
MIIEmzCCAoOgAwIBAgICEAMwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCREUx
EDAOBgNVBAgMB0JhdmFyaWExDzANBgNVBAcMBk11bmljaDEMMAoGA1UECgwDQk1X
MQ8wDQYDVQQLDAZDYXIgSVQxEjAQBgNVBAMMCVJvb3QgQ0EgMTAeFw0xNzAzMjcx
OTAwMzhaFw00NDA4MTIxOTAwMzhaMFkxCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdC
YXZhcmlhMQwwCgYDVQQKDANCTVcxDzANBgNVBAsMBkNhciBJVDEZMBcGA1UEAwwQ
SW50ZW1lZGlhdGUgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AO8qwEF+yiQEn+rdxAEP/IdWEAccu4Di9RUVmPncitsHQVuHjRUlzwJ6jjeZ674x
oXyAbXQNQfBtzJTcHPgObTAMipdpJweN0RMeF2J3j03etDWHjpNQepcxuFKcfCr8
CHJFYy7t5W2zgEc9UsjwhqwZvRLE/NwtSfGNUsy71h5kCRhsfSwlqedhqmgzfYtA
D9wh1b7o/zCh92H+W+zlwvLvp9Fn2baFfhEQpY324pQ753PronkuVxKyJoPtKC/w
j/SoTM7/0DAzHgE0++4NmfwzXZ2jVSZYIyQQCI0iYFgobAC/sHEKbjZL0hdeQm3S
UqcWZ4tHGU50AT8FR/gppZECAwEAAaNjMGEwHQYDVR0OBBYEFBC7eqGCFs/OIv/r
meG3ndMNfTKCMB8GA1UdIwQYMBaAFNMUo4azb3BwlBom1iA40BHPp4qyMA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQBs
EB+RpTUTyBIWQ4Hkg25ZKxbIdDmt0Uiu2jBTRx4kF2zRQ/xKnOls49QRJs9U15VJ
8F000XlM34s6DGl0cdUjdQY9LJCKJ24LltQGvEMgCGVcZzqG8IKrzuDTfu+CLwbs
eECO1cGNVkXa8ZsZEt8KtItCSzEZctLNOXF4sIFQr2DJzGcwA+umfK6dJ9E5SeHk
x2VHYjVx6iavKFQNSDy8EsS78jlKAZONqoCy/PMDOaqKbF9m7rNt4VL+BecJHbzC
mxjTHVWgfeN4nJgqo07ggDlHjmsoVYXl2EjluuReZLbqVxA/r7NcKDT7/gJyrdlG
OGwYpzkhqAsofgcHZwPocBq1Nwt9HXmA1WSw++R8KmJ0gf47bRxP1hv/BtQWuvZi
I/G/KVbh5K4nHR6oPuOJ5JXx164vAIPxd5tnqQGQHo+6lTNIsb6eueDTCba/NxbH
WI/ur6MJMEtfZGruLfU7XL970mcWMdwUh/MqSc7ffEA2Pj6aLnffmvqxdMEhuhTu
TMgis07hulAnaaBCrb1xiGFYC/tGcJ+558nycS4XiFjU0Nsh1zzubTum51ry+fSz
E6sliUj/gfWDpEur75FEoG9gYhRl3rI3Rj34al2DP5no7J2KCrq59lK3WI+vByYM
uRZLQUBt1w+r1qEakvSIoinjrmS616qfkOBPHJEkvQ==
-----END CERTIFICATE-----)"
};
\endcode
In the example bellow we are loading two certificates from their respective PEM strings
and then are verifying if the intCert was signed by the rootCert
\code{.cpp}
X509Certificate rootCert = X509Certificate::fromPEM("rootPemString");
X509Certificate intCert = X509Certificate::fromPEM("intPemString");

void X509Certificate::verify(rootCert, intCert);
\endcode



X509Certificate class also provides methods to get various types of information like issuer
and subject distinguished name, certificate validity, serial number and public key.
\code{.cpp}
X509Certificate cert = X509Certificate::fromPEM(intPemString);

DistinguishedName issDN = cert.getIssuerDistinguishedName();
DistinguishedName subjDN = cert.getSubjectDistinguishedName();
uint64_t serialN = cert.getSerialNumber();
std::chrono::system_clock::time_point validity = X509Certificate::getNotAfter();
AsymmetricPublicKey pubK = cert.getPublicKey();
\endcode

A certificate can be written to a PEM format. 
\code{.cpp}
X509Certificate cert; 
std::string certToPem = cert.toPEM();
\endcode

It's possible to add more parameters to the Certificate verification by providing the verify method
with a VerificationCtx Object where we can set a CRL (certificate revocation list),
a time check verification and others.
In the example bellow we can see an example where we create a context that enables 
a time check verification.
\code{.cpp}
X509Certificate cert = X509Certificate::fromPEM(intPemString);
VerificationContext ctx = ctx.setVerificationCheckTime(cert.getNotBeforeAsn1() - Asn1Time::Seconds(1));
void cert.verify(ctx);
\endcode

