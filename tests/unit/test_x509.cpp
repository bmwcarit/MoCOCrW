/*
 * #%L
 * %%
 * Copyright (C) 2018 BMW Car IT GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
#include <fstream>
#include <algorithm>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "IOUtils.h"

#include "x509.cpp"

using namespace std::string_literals;

using namespace mococrw;
using namespace mococrw::openssl;

std::string corruptPEM(const std::string &pem)
{
    std::vector<char> tokenBytes{pem.cbegin(), pem.cend()};
    if (tokenBytes.size() < 64) {
        throw std::runtime_error("Could not corrupt token. String is too short");
    }
    tokenBytes.at(63) ^= 0xff;
    return std::string{tokenBytes.cbegin(), tokenBytes.cend()};
}

class X509Test : public ::testing::Test
{
public:
    void SetUp() override;
protected:
    static const std::string _pemString;
    static const std::string _shortSerialPemString;
    static const std::string _negativeSerialPemString;
    static const std::string _pemChainOfThree;
    std::string _pemChainNoNewlines;
    static const std::string _pemChainInvalid;
    static const std::string _certWithGivenName;
    static const std::string _eccRootKeyPem;
    static const std::string _eccIntermediateKeyPem;
    static const std::string _eccUserKeyPem;
    static const std::string _pemChainEcc;

    X509Certificate _cert = X509Certificate::fromPEM(_pemString);

    std::unique_ptr<X509Certificate> _root1;
    std::unique_ptr<X509Certificate> _root1_future;
    std::unique_ptr<X509Certificate> _root1_expired;
    std::unique_ptr<X509Certificate> _root1_int1;
    std::unique_ptr<X509Certificate> _root1_int1_cert1;

    std::unique_ptr<X509Certificate> _root2;

    std::unique_ptr<X509Certificate> _year1970;
    std::unique_ptr<X509Certificate> _year2049;
    std::unique_ptr<X509Certificate> _year2050;
    std::unique_ptr<X509Certificate> _year9999;

    std::unique_ptr<AsymmetricPublicKey> _root1_pubkey;

    std::unique_ptr<X509Certificate> _eccRoot;
    std::unique_ptr<X509Certificate> _eccIntermediate;
    std::unique_ptr<X509Certificate> _eccUser;
};

void X509Test::SetUp()
{
    _cert = X509Certificate::fromPEM(_pemString);

    _root1 = std::make_unique<X509Certificate>(loadCertFromFile("root1.pem"));
    _root1_future = std::make_unique<X509Certificate>(loadCertFromFile("root1.future.pem"));
    _root1_expired = std::make_unique<X509Certificate>(loadCertFromFile("root1.expired.pem"));
    _root1_int1 = std::make_unique<X509Certificate>(loadCertFromFile("root1.int1.pem"));
    _root1_int1_cert1 = std::make_unique<X509Certificate>(loadCertFromFile("root1.int1.cert1.pem"));

    _root2 = std::make_unique<X509Certificate>(loadCertFromFile("root2.pem"));

    _year1970 = std::make_unique<X509Certificate>(loadCertFromFile("year1970.pem"));
    _year2049 = std::make_unique<X509Certificate>(loadCertFromFile("year2049.pem"));
    _year2050 = std::make_unique<X509Certificate>(loadCertFromFile("year2050.pem"));
    _year9999 = std::make_unique<X509Certificate>(loadCertFromFile("year9999.pem"));

    _root1_pubkey = std::make_unique<AsymmetricPublicKey>(loadPubkeyFromFile("root1.pubkey.pem"));

    _pemChainNoNewlines = _pemChainOfThree;
    _pemChainNoNewlines.erase(
        std::remove_if(_pemChainNoNewlines.begin(), _pemChainNoNewlines.end(),
                       [] (auto c) { return c == '\n'; }),
        _pemChainNoNewlines.end());

    _eccRoot = std::make_unique<X509Certificate>(loadCertFromFile("eccRootCertificate.pem"));
    _eccIntermediate = std::make_unique<X509Certificate>(loadCertFromFile("eccIntermediateCertificate.pem"));
    _eccUser = std::make_unique<X509Certificate>(loadCertFromFile("eccUserCertificate.pem"));

}

const std::string X509Test::_pemString{R"(-----BEGIN CERTIFICATE-----
MIIEUDCCAzigAwIBAgIJAO1DR/R6S8YsMA0GCSqGSIb3DQEBCwUAMIG8MQswCQYD
VQQGEwJERTEQMA4GA1UECAwHbmViZW5hbjENMAsGA1UEBwwEb2JlbjERMA8GA1UE
CgwITGludXggQUcxFjAUBgNVBAsMDUxpbnV4IFN1cHBvcnQxIjAgBgkqhkiG9w0B
CQEWE3N1cHBvcnRAZXhhbXBsZS5jb20xKTAnBgNVBAUTIDA4RTM2REQ1MDE5NDE0
MzIzNThBRkU4MjU2QkM2RUZEMRIwEAYDVQQDDAlJbUFUZWFwb3QwHhcNMTgwNDA5
MTMwMzUzWhcNNDUwODI1MTMwMzUzWjCBvDELMAkGA1UEBhMCREUxEDAOBgNVBAgM
B25lYmVuYW4xDTALBgNVBAcMBG9iZW4xETAPBgNVBAoMCExpbnV4IEFHMRYwFAYD
VQQLDA1MaW51eCBTdXBwb3J0MSIwIAYJKoZIhvcNAQkBFhNzdXBwb3J0QGV4YW1w
bGUuY29tMSkwJwYDVQQFEyAwOEUzNkRENTAxOTQxNDMyMzU4QUZFODI1NkJDNkVG
RDESMBAGA1UEAwwJSW1BVGVhcG90MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEArXHJRfDgJTuvUYwGj/uuXveDUvsMvKU3KZim0lfcSd88xNvgml1wFIEu
ovER/ISKzYuhdQrV/W5ujtGj+5XEk/vMlrhviQYaPLTFMipNKhxOJ7eKtd9Lflsz
oa/3+nQVsWHgyyHdIKSrM2Ayna2HnMgQZOT3xolHVUX4V3Oip7iiOED1igbFCDzi
krL4fd6EpJHxfGa983Snya7CEm3caN4Mq78GSsDuojSn17DNoCnePSrNB6q77pWk
FVlmqeVdtnABoJ/zmdON8i1CnNsdguHfAf1zXYzmpRjfdkb1e/PSmQe0PArJ/dyS
UpEUCLPlBOQOU22rLXsAFVVTAfRF4wIDAQABo1MwUTAdBgNVHQ4EFgQU/2H7Z/yC
UAH3bbrf3GAp0MDx3+swHwYDVR0jBBgwFoAU/2H7Z/yCUAH3bbrf3GAp0MDx3+sw
DwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAZ6lSJotDC5I13HK3
2Q4woe8pbxt8KI7qhrl/7sWTT/UBSVj4ZWoyLJiE8XQjXw8EWODKsECeWI0Ztxib
iusTx0kuW5lo8EPLqW7hG4aD7sZCmslBZjB3kGU8iH4AGdIswmC7pzraHdKRWpb7
a+nduZ+dBBL7f+jPnCV6y0uRJVQZ3IinoZGeZyFazfq4tWraIotE7STkQpoiM8TG
4vj2kM+h9miQEbYAyg6z4uwoiK4eqOvwJdqTxjHufDbRK1WmdrieU8psr6lebWP+
KuAcbGt8ba8eeJrDJoBKRB6y4K/LM7Z/Ajq4548PduDyFuKqC2qlw0LAWUbQprPX
2EI7Tw==
-----END CERTIFICATE-----)"
};

const std::string X509Test::_shortSerialPemString{
R"(-----BEGIN CERTIFICATE-----
MIICOTCCAeOgAwIBAgIBDDANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJERTEb
MBkGA1UECAwSQmFkZW4tV3VlcnR0ZW1iZXJnMQwwCgYDVQQHDANVbG0xGDAWBgNV
BAoMD0JNVyBDYXIgSVQgR21iSDENMAsGA1UECwwESkMtNzEZMBcGA1UEAwwQVGVz
dCBDZXJ0aWZpY2F0ZTAeFw0xNzA3MjUxMjAyNTJaFw0xODA3MjUxMjAyNTJaMHwx
CzAJBgNVBAYTAkRFMRswGQYDVQQIDBJCYWRlbi1XdWVydHRlbWJlcmcxDDAKBgNV
BAcMA1VsbTEYMBYGA1UECgwPQk1XIENhciBJVCBHbWJIMQ0wCwYDVQQLDARKQy03
MRkwFwYDVQQDDBBUZXN0IENlcnRpZmljYXRlMFwwDQYJKoZIhvcNAQEBBQADSwAw
SAJBAPBv9TuHRI+t28ONKkKspleukIcGmHx/zDBpoPYRUU5VzT3nNPLbxD2MOxfI
Tv6r+8ielFOrnabK/6LcLadin20CAwEAAaNQME4wHQYDVR0OBBYEFBBwzzzDSMfC
uuL/aoaa9HwgPUefMB8GA1UdIwQYMBaAFBBwzzzDSMfCuuL/aoaa9HwgPUefMAwG
A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADQQBFBuE9h4TrimeKhqbCPEmkUlX0
cS0ri/kzH2BN2lM1Jt+NdPeMTGnkIiLwPoIaPSFeTZjz5Ka0mpq2wClzk2Ci
-----END CERTIFICATE-----)"};

const std::string X509Test::_negativeSerialPemString{
R"(-----BEGIN CERTIFICATE-----
MIICQzCCAe2gAwIBAgIB1jANBgkqhkiG9w0BAQsFADCBgDELMAkGA1UEBhMCREUx
GzAZBgNVBAgMEkJhZGVuLVd1ZXJ0dGVtYmVyZzEMMAoGA1UEBwwDVWxtMRgwFgYD
VQQKDA9CTVcgQ2FyIElUIEdtYkgxDTALBgNVBAsMBEpDLTcxHTAbBgNVBAMMFE5l
Z2F0aXZlIFNlcmlhbCBUZXN0MB4XDTE3MDcyNTEyMTE1NVoXDTE4MDcyNTEyMTE1
NVowgYAxCzAJBgNVBAYTAkRFMRswGQYDVQQIDBJCYWRlbi1XdWVydHRlbWJlcmcx
DDAKBgNVBAcMA1VsbTEYMBYGA1UECgwPQk1XIENhciBJVCBHbWJIMQ0wCwYDVQQL
DARKQy03MR0wGwYDVQQDDBROZWdhdGl2ZSBTZXJpYWwgVGVzdDBcMA0GCSqGSIb3
DQEBAQUAA0sAMEgCQQDXKboXa5QW0I7JknewmLQqRTOp0QcDsrck3THEeaSBRNyb
04uQFZGftdsuC2b9jr1k8NCiuy3Su81tn4ku1dIPAgMBAAGjUDBOMB0GA1UdDgQW
BBRu6KAISE1V4jhYuiyb3iEZTf2ijDAfBgNVHSMEGDAWgBRu6KAISE1V4jhYuiyb
3iEZTf2ijDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA0EAENPsu/If+1Ir
YMjWHTmu7K7pwJxYg8QBdfhVbnc5qHK+sZk1zHh+ng7bW1QZIvitKhW8hnUiwz3O
wvM4cGGE+Q==
-----END CERTIFICATE-----)"
};

// This is root1, root1.int1, root1.int1.cert1

const std::string X509Test::_pemChainOfThree{
R"(-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIID+jCCAuKgAwIBAgICEAEwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCREUx
EDAOBgNVBAgMB0JhdmFyaWExDDAKBgNVBAoMA0JNVzEPMA0GA1UECwwGQ2FyIElU
MRkwFwYDVQQDDBBJbnRlbWVkaWF0ZSBDQSAxMB4XDTE3MDMyNzE0MTcwNFoXDTQ0
MDgxMjE0MTcwNFowaTELMAkGA1UEBhMCREUxEDAOBgNVBAgMB0JhdmFyaWExDDAK
BgNVBAoMA0JNVzEPMA0GA1UECwwGQ2FyIElUMSkwJwYDVQQDDCBDZXJ0aWZpY2F0
ZSB1bmRlciBJbnRlcm1lZGlhdGUgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAMqp3RKSYuGJRJfnqFHJJaR6GNmtacbwRaWuTHKjgyhe6osPwO4FG0hE
9U3BKfh1oHiAp49B3C2qqIdFzmx07pS9i2hMSpzkdN1hzzznLpkuCw7jatbH66+T
jz+AqTcsiXjDYQXk579wcULJb7QYXEBeMrAymo+yTcL5y3GwSifiveiiOCOZXV4/
zD1JKV/CpZESU14DLepZoBtF6/TSfMHeiG4M1Vsxvj5pCLU3O2TEtPpys8wRiUgf
6+ndrZWs+Q8GCpa1JbAJYVo5mZ+DOOCd0MrtBJ55s6vGZSJLiJiK1jDfiyusMZF8
J0mEdUXQbsuJonkfEvxrNGYMBERBbUcCAwEAAaOBuzCBuDAJBgNVHRMEAjAAMBEG
CWCGSAGG+EIBAQQEAwIHgDAzBglghkgBhvhCAQ0EJhYkT3BlblNTTCBHZW5lcmF0
ZWQgQ2xpZW50IENlcnRpZmljYXRlMB0GA1UdDgQWBBSWfaGiTd1ay6skkx9LT3Dc
i8EBjTAfBgNVHSMEGDAWgBQQu3qhghbPziL/65nht53TDX0ygjAOBgNVHQ8BAf8E
BAMCBeAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBAOJg
NbJsGNs6/zJ35lMjAh3msbZUTPD0HfI1ko3ZWe3US9SzhvtVjigt8xJrlbP/cOWa
tKEfKmZ0SnHNyqKp6UTPNgkK03XxvNAjXy7m3syokrJG0vcOLA3PUSFFpLaixcU9
qzdsUzZtraSqwvoTmOrmvhzzaNBglZpFhScGqVQsZYbMEKbSkNWbGj+E/0GoAjPp
FM8GVeGdLPfBfpDybV6RlgAFmuRt6SKdJ1eZvyp6bJfLN8RaoKMXh7ZTkCyOrUhO
3qCuAUn21XS9k7vu6kJZRP8p7gBZb9nLnj/PIlP4ZrrgLfpZr0WkKDDCOZKeId/4
i1WWJ4xDbDzyjalWgQI=
-----END CERTIFICATE-----)"
};

const std::string X509Test::_pemChainInvalid{
R"(-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----BLA
-----BEGIN CERTIFICATE-----
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

const std::string X509Test::_certWithGivenName{
R"(-----BEGIN CERTIFICATE-----
MIIC6TCCAo+gAwIBAgIJAN6EkERSsPfKMAoGCCqGSM49BAMCMIHOMQswCQYDVQQG
EwJERTEQMA4GA1UECAwHbmViZW5hbjENMAsGA1UEBwwEb2JlbjEQMA4GA1UECgwH
TGludXhBRzEVMBMGA1UECwwMTGludXhTdXBwb3J0MSIwIAYJKoZIhvcNAQkBFhNz
dXBwb3J0QGV4YW1wbGUuY29tMSkwJwYDVQQFEyAwOEUzNkRENTAxOTQxNDMyMzU4
QUZFODI1NkJDNkVGRDESMBAGA1UEAwwJSW1BVGVhcG90MRIwEAYDVQQqDAlHaXZl
bk5hbWUwHhcNMTgxMTE5MTA1ODE3WhcNMjgxMTE2MTA1ODE3WjCBzjELMAkGA1UE
BhMCREUxEDAOBgNVBAgMB25lYmVuYW4xDTALBgNVBAcMBG9iZW4xEDAOBgNVBAoM
B0xpbnV4QUcxFTATBgNVBAsMDExpbnV4U3VwcG9ydDEiMCAGCSqGSIb3DQEJARYT
c3VwcG9ydEBleGFtcGxlLmNvbTEpMCcGA1UEBRMgMDhFMzZERDUwMTk0MTQzMjM1
OEFGRTgyNTZCQzZFRkQxEjAQBgNVBAMMCUltQVRlYXBvdDESMBAGA1UEKgwJR2l2
ZW5OYW1lMFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABGSm7I5r5lx58NEUdL4y
cmGNhzvxm+YitaQMiAaBIC+fmd3/J5DWtEvtpXDc68wqBImN6uoL/cNfIES703Y3
xJGjUzBRMB0GA1UdDgQWBBSvUgPk/0OgqCjq51t0uFte9/uUvzAfBgNVHSMEGDAW
gBSvUgPk/0OgqCjq51t0uFte9/uUvzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
BAMCA0gAMEUCIFMm751uiLYek33gkcLHyCMdXntcwXUdgoEtOuq04Yr7AiEAk62k
0Ct1NJmoJM1Hb88ID7WRHzwrkn5YLsc57UOKMYo=
-----END CERTIFICATE-----)"
};

const std::string X509Test::_eccRootKeyPem{
R"(-----BEGIN PRIVATE KEY-----
MIHCAgEAMBAGByqGSM49AgEGBSuBBAAkBIGqMIGnAgEBBDQAF2zFhKyxJiI7bGvG
Mw9rq7DUvrqTDJMHeRttpsZc0i9tFbvmaT2J5U39/RkseDha2b87oWwDagAEAAdj
oVwkpy9CPA8RU3sd0aXV/XnHw5nE7HgINd6ApxCaknRebk4Vgbgz04588YqjqQpQ
TAA+hxkUt1ZInurAHTt/ECQpvt1YOTBgNigakbLzq1LsbbyLWJsH5diall6Is+lg
y2Mu1EA=
-----END PRIVATE KEY-----)"
};

const std::string X509Test::_eccIntermediateKeyPem{
R"(-----BEGIN PRIVATE KEY-----
MIHCAgEAMBAGByqGSM49AgEGBSuBBAAkBIGqMIGnAgEBBDQAAQuTNqP1ipk57oZm
FcB1ZCEYY4R6Y6V51DA+taE2zBuvpejV8ePjASYNdjewoYxxwkuHoWwDagAEACOv
gIc+P+nKb1cZh0ikhhG7z+WbGJivBM97H+8PdiZio4Zk8P659OLtiGh0EZ/xG7YB
UAHUnp3pkDj5/jZ6ufhbiN96zpXf83vvtqI1Nhf9Ej0rAyVs5vpSjp8P97KDNuS6
btCxINI=
-----END PRIVATE KEY-----)"
};

const std::string X509Test::_eccUserKeyPem{
R"(-----BEGIN PRIVATE KEY-----
MIHCAgEAMBAGByqGSM49AgEGBSuBBAAkBIGqMIGnAgEBBDQAcas1glPO4GSllQ1E
3xy9ufqi4IuymIvc2A4OpEYu3Eo/sPxuQhpwmuobglnQvyRH7TrsoWwDagAEABGO
oeaF7FX5VB0JFELIUPO+8cD3LmlioJR9ckUhbPUhxza4bflUQYXOuLFaZ3LncVsF
7ADykWyFcm2oQ4mPM0sp6D8WUBkbqG4t7Q2RP9CZrGH7hTcdEDy6LgHkDtjLG3eM
PwSgThU=
-----END PRIVATE KEY-----)"
};

const std::string X509Test::_pemChainEcc{
R"(-----BEGIN CERTIFICATE-----
MIICXDCCAd2gAwIBAgIJAIIti+pyO05eMAoGCCqGSM49BAMCMFwxCzAJBgNVBAYT
AlBUMQ4wDAYDVQQIDAVQb3J0bzEOMAwGA1UEBwwFUG9ydG8xITAfBgNVBAoMGElu
dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEKMAgGA1UEAwwBQTAeFw0xODExMjkxOTQ0
MThaFw0xOTExMjkxOTQ0MThaMFwxCzAJBgNVBAYTAlBUMQ4wDAYDVQQIDAVQb3J0
bzEOMAwGA1UEBwwFUG9ydG8xITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5
IEx0ZDEKMAgGA1UEAwwBQTB+MBAGByqGSM49AgEGBSuBBAAkA2oABAAHY6FcJKcv
QjwPEVN7HdGl1f15x8OZxOx4CDXegKcQmpJ0Xm5OFYG4M9OOfPGKo6kKUEwAPocZ
FLdWSJ7qwB07fxAkKb7dWDkwYDYoGpGy86tS7G28i1ibB+XYmpZeiLPpYMtjLtRA
o2MwYTAdBgNVHQ4EFgQUba0P7fHnmLen9HYoILCBwp01X3AwHwYDVR0jBBgwFoAU
ba0P7fHnmLen9HYoILCBwp01X3AwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E
BAMCAYYwCgYIKoZIzj0EAwIDbQAwagIzf9lXvPqvXNBormiFLHguXdZRVH4BeTnd
AbQZ6ouNSt8R2kENgI1NQAOFvAu4ozwdebIoAjM1y9kcKfvhdPySULLNWThOG5qv
g4kKHAXMlMO6sWRbfjZcupG2CjRWcowfv14jsB8D/go=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICXjCCAd+gAwIBAgICEAAwCgYIKoZIzj0EAwIwXDELMAkGA1UEBhMCUFQxDjAM
BgNVBAgMBVBvcnRvMQ4wDAYDVQQHDAVQb3J0bzEhMB8GA1UECgwYSW50ZXJuZXQg
V2lkZ2l0cyBQdHkgTHRkMQowCAYDVQQDDAFBMCIYDzIwMTAwMTAxMDAwMDAwWhgP
MjA0NTAxMDEwMDAwMDBaMF4xCzAJBgNVBAYTAlBUMQ8wDQYDVQQIDAZMaXNib24x
DzANBgNVBAcMBkxpc2JvbjEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkg
THRkMQowCAYDVQQDDAFCMH4wEAYHKoZIzj0CAQYFK4EEACQDagAEACOvgIc+P+nK
b1cZh0ikhhG7z+WbGJivBM97H+8PdiZio4Zk8P659OLtiGh0EZ/xG7YBUAHUnp3p
kDj5/jZ6ufhbiN96zpXf83vvtqI1Nhf9Ej0rAyVs5vpSjp8P97KDNuS6btCxINKj
ZjBkMB0GA1UdDgQWBBSCc34AMYWV0fzPjMntuZumg8tASjAfBgNVHSMEGDAWgBRt
rQ/t8eeYt6f0diggsIHCnTVfcDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB
/wQEAwIBhjAKBggqhkjOPQQDAgNtADBqAjNDhS00P5ZqSsKzP/TgahO9R53hsEsl
scoDEGE17WYgbY/qPzcrHwcl50UYteDS1zHGKS8CMy91h7PAoqTkj4k9/9uUgDo8
VqVeNrZnQNjlqvqDuWlkuMEJDfxZFGNhLNXUJQ3WGeR2mw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICtjCCAjegAwIBAgICEAEwCgYIKoZIzj0EAwIwXjELMAkGA1UEBhMCUFQxDzAN
BgNVBAgMBkxpc2JvbjEPMA0GA1UEBwwGTGlzYm9uMSEwHwYDVQQKDBhJbnRlcm5l
dCBXaWRnaXRzIFB0eSBMdGQxCjAIBgNVBAMMAUIwIhgPMjAxMDAxMDEwMDAwMDBa
GA8yMDQ1MDEwMTAwMDAwMFowXjELMAkGA1UEBhMCREUxDzANBgNVBAgMBk11bmlj
aDEPMA0GA1UEBwwGTXVuaWNoMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0
eSBMdGQxCjAIBgNVBAMMAUMwfjAQBgcqhkjOPQIBBgUrgQQAJANqAAQAEY6h5oXs
VflUHQkUQshQ877xwPcuaWKglH1yRSFs9SHHNrht+VRBhc64sVpncudxWwXsAPKR
bIVybahDiY8zSynoPxZQGRuobi3tDZE/0JmsYfuFNx0QPLouAeQO2Msbd4w/BKBO
FaOBuzCBuDAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIHgDAzBglghkgBhvhC
AQ0EJhYkT3BlblNTTCBHZW5lcmF0ZWQgQ2xpZW50IENlcnRpZmljYXRlMB0GA1Ud
DgQWBBQw1qaByB+Yyvz06/5PALaAao/f/TAfBgNVHSMEGDAWgBSCc34AMYWV0fzP
jMntuZumg8tASjAOBgNVHQ8BAf8EBAMCBeAwEwYDVR0lBAwwCgYIKwYBBQUHAwIw
CgYIKoZIzj0EAwIDbQAwagIzcpeeAf2n/fWLzeRVjX7R+/oWuB6OkzOrHI0UsVLT
GDp3DIfB0qcz4hCd2B2SXAS2GcrpAjMvVbewrWuwJhVvgjlwhdzpO6AS65zzuwFb
//1lXAyymwh7s+tNhq36qxiNKr5i4DncVqI=
-----END CERTIFICATE-----)"
};

TEST_F(X509Test, testParsingX509CertificateFromPem)
{
    using ::testing::NotNull;
    ASSERT_THAT(_cert.internal(), NotNull());
    const auto corruptedPem = corruptPEM(_pemString);
    ASSERT_THROW(X509Certificate::fromPEM(corruptedPem), OpenSSLException);
}

TEST_F(X509Test, testParsingIssuerAndSubject)
{
    using ::testing::Eq;
    auto subject = _cert.getSubjectDistinguishedName();
    auto issuer = _cert.getIssuerDistinguishedName();

    ASSERT_THAT(subject.commonName(), Eq("ImATeapot"));
    ASSERT_THAT(subject.countryName(), Eq("DE"));
    ASSERT_THAT(subject.localityName(), Eq("oben"));
    ASSERT_THAT(subject.stateOrProvinceName(), Eq("nebenan"));
    ASSERT_THAT(subject.organizationalUnitName(), Eq("Linux Support"));
    ASSERT_THAT(subject.organizationName(), Eq("Linux AG"));
    ASSERT_THAT(subject.pkcs9EmailAddress(), Eq("support@example.com"));
    ASSERT_THAT(subject.serialNumber(), Eq("08E36DD501941432358AFE8256BC6EFD"));
}

TEST_F(X509Test, testLoadPEMCertFromFileDirectly)
{
    using ::testing::NotNull;
    ASSERT_NO_THROW({
        auto cert = X509Certificate::fromPEMFile("root1.pem");
        ASSERT_THAT(cert.internal(), NotNull());
    });
}

TEST_F(X509Test, testLoadDERCert)
{
    using ::testing::NotNull;
    ASSERT_NO_THROW({
        auto cert = loadCertFromDERFile("root1.der");
        ASSERT_THAT(cert.internal(), NotNull());
    });
}

TEST_F(X509Test, testLoadDERCertFromFileDirectly)
{
    using ::testing::NotNull;
    ASSERT_NO_THROW({
        auto cert = X509Certificate::fromDERFile("root1.der");
        ASSERT_THAT(cert.internal(), NotNull());
    });
}

TEST_F(X509Test, testNotBeforeWorking)
{
    /* Root1
     * Not Before: Mar 27 12:47:11 2017 GMT
     * d = datetime.datetime(2017, 3, 27, 12, 47, 11, tzinfo=datetime.timezone.utc)
     * d.timestamp()
     * 1490618831.0
     */
    auto notBeforeRoot1 = _root1->getNotBefore();
    EXPECT_TRUE(std::chrono::system_clock::to_time_t(notBeforeRoot1) == 1490618831);
    EXPECT_TRUE(notBeforeRoot1 == std::chrono::system_clock::from_time_t(1490618831));

    /* root1_int1
     * Not Before: Mar 27 19:00:38 2017 GMT
     * d = datetime.datetime(2017, 3, 27, 19, 00, 38, tzinfo=datetime.timezone.utc)
     * d.timestamp()
     * 1490641238.0
     */
    auto notBeforeRoot1_Int1 = _root1_int1->getNotBefore();
    EXPECT_TRUE(std::chrono::system_clock::to_time_t(notBeforeRoot1_Int1) == 1490641238);
    EXPECT_TRUE(notBeforeRoot1_Int1 == std::chrono::system_clock::from_time_t(1490641238));
}

TEST_F(X509Test, testNotAfterWorking)
{
    /* Root1
     * Not After : Aug 12 12:47:11 2044 GMT
     * d = datetime.datetime(2044, 8, 12, 12, 47, 11, tzinfo=datetime.timezone.utc)
     * d.timestamp()
     * 2354618831.0
     */
    auto notAfterRoot1 = _root1->getNotAfter();
    EXPECT_TRUE(std::chrono::system_clock::to_time_t(notAfterRoot1) == 2354618831);
    EXPECT_TRUE(notAfterRoot1 == std::chrono::system_clock::from_time_t(2354618831));

    /* root1_int1
     * Not After : Aug 12 19:00:38 2044 GMT
     * d = datetime.datetime(2044, 8, 12, 19, 00, 38, tzinfo=datetime.timezone.utc)
     * d.timestamp()
     * 2354641238.0
     */
    auto notAfterRoot1_Int1 = _root1_int1->getNotAfter();
    EXPECT_TRUE(std::chrono::system_clock::to_time_t(notAfterRoot1_Int1) == 2354641238);
    EXPECT_TRUE(notAfterRoot1_Int1 == std::chrono::system_clock::from_time_t(2354641238));
}

TEST_F(X509Test, test1970EdgeCaseAsn1DateShort)
{
    // Not Before: Jan  1 00:01:00 1970 GMT
    // Not After : May 16 00:01:00 9952 GMT
    
    auto notBeforeAsn1 = _year1970->getNotBeforeAsn1();
    auto notAfterAsn1 = _year1970->getNotAfterAsn1();

    auto expectedNotBeforeAsn1 = Asn1Time::fromString("700101000100Z");
    EXPECT_EQ(notBeforeAsn1, expectedNotBeforeAsn1);

    auto expectedDateAfterAsn1 = Asn1Time::fromString("99520516000100Z");
    EXPECT_EQ(notAfterAsn1, expectedDateAfterAsn1);
}

TEST_F(X509Test, test2049EdgeCaseAsn1DateShort)
{
    // Not Before: Dec 31 23:59:00 2049 GMT
    // Not After : Sep 20 23:59:00 2079 GMT

    auto notBeforeAsn1 = _year2049->getNotBeforeAsn1();
    auto notAfterAsn1 = _year2049->getNotAfterAsn1();

    auto expectedNotBeforeAsn1 = Asn1Time::fromString("491231235900Z");
    EXPECT_EQ(notBeforeAsn1, expectedNotBeforeAsn1);

    auto expectedDateAfterAsn1 = Asn1Time::fromString("20790920235900Z");
    EXPECT_EQ(notAfterAsn1, expectedDateAfterAsn1);
}

TEST_F(X509Test, test2050EdgeCaseAsn1DateLong)
{
    // Not Before: Jan  1 00:01:00 2050 GMT
    // Not After : Sep 21 00:01:00 2079 GMT

    auto notBeforeAsn1 = _year2050->getNotBeforeAsn1();
    auto notAfterAsn1 = _year2050->getNotAfterAsn1();

    auto expectedNotBeforeAsn1 = Asn1Time::fromString("20500101000100Z");
    EXPECT_EQ(notBeforeAsn1, expectedNotBeforeAsn1);

    auto expectedDateAfterAsn1 = Asn1Time::fromString("20790921000100Z");
    EXPECT_EQ(notAfterAsn1, expectedDateAfterAsn1);
}

TEST_F(X509Test, test9999EdgeCaseAsn1DateLong)
{
    // Not Before: Aug 16 23:59:00 2017 GMT
    // Not After : Dec 31 23:59:00 9999 GMT

    auto notBeforeAsn1 = _year9999->getNotBeforeAsn1();
    auto notAfterAsn1 = _year9999->getNotAfterAsn1();

    auto expectedNotBeforeAsn1 = Asn1Time::fromString("170816235900Z");
    EXPECT_EQ(notBeforeAsn1, expectedNotBeforeAsn1);

    auto expectedDateAfterAsn1 = Asn1Time::fromString("99991231235900Z");
    EXPECT_EQ(notAfterAsn1, expectedDateAfterAsn1);
}

TEST_F(X509Test, testIfPubkeyIsCorrectlyExtractedFromCertificate)
{
    EXPECT_EQ(_root1->getPublicKey(), *_root1_pubkey);

    auto rootPrivKey = AsymmetricKeypair::readPrivateKeyFromPEM(_eccRootKeyPem, "");
    EXPECT_EQ(_eccRoot->getPublicKey().publicKeyToPem(), rootPrivKey.publicKeyToPem());

    auto intPrivKey = AsymmetricKeypair::readPrivateKeyFromPEM(_eccIntermediateKeyPem, "");
    EXPECT_EQ(_eccIntermediate->getPublicKey().publicKeyToPem(), intPrivKey.publicKeyToPem());

    auto usrPrivKey = AsymmetricKeypair::readPrivateKeyFromPEM(_eccUserKeyPem, "");
    EXPECT_EQ(_eccUser->getPublicKey().publicKeyToPem(), usrPrivKey.publicKeyToPem());
}

TEST_F(X509Test, testIfPubkeyDoesNotMatchOtherCertificate)
{
    EXPECT_NE(_root2->getPublicKey(), *_root1_pubkey);

    EXPECT_NE(_eccRoot->getPublicKey().publicKeyToPem(), _root1_pubkey->publicKeyToPem());
}

TEST_F(X509Test, testLoadX509Chain)
{
    EXPECT_NO_THROW({
        auto pemChain = util::loadPEMChain(_pemChainOfThree);

        EXPECT_EQ(pemChain.size(), 3);

        // check that the correct certificates are loaded in the correctorder
        EXPECT_EQ(pemChain[0].getSubjectDistinguishedName(),
                  _root1->getSubjectDistinguishedName());
        EXPECT_EQ(pemChain[1].getSubjectDistinguishedName(),
                  _root1_int1->getSubjectDistinguishedName());
        EXPECT_EQ(pemChain[2].getSubjectDistinguishedName(),
                  _root1_int1_cert1->getSubjectDistinguishedName());
    });


    EXPECT_NO_THROW({
        auto pemChain = util::loadPEMChain(_pemChainEcc);

        EXPECT_EQ(pemChain.size(), 3);

        // check that the correct certificates are loaded in the correctorder
        EXPECT_EQ(pemChain[0].getSubjectDistinguishedName(),
                  _eccRoot->getSubjectDistinguishedName());
        EXPECT_EQ(pemChain[1].getSubjectDistinguishedName(),
                  _eccIntermediate->getSubjectDistinguishedName());
        EXPECT_EQ(pemChain[2].getSubjectDistinguishedName(),
                  _eccUser->getSubjectDistinguishedName());
    });
}

TEST_F(X509Test, testLoadX509ChainNoNewlines)
{
    EXPECT_NO_THROW({
        auto pemChain = util::loadPEMChain(_pemChainNoNewlines);

        EXPECT_EQ(pemChain.size(), 3);

        // check that the correct certificates are loaded in the correctorder
        EXPECT_EQ(pemChain[0].getSubjectDistinguishedName(),
                  _root1->getSubjectDistinguishedName());
        EXPECT_EQ(pemChain[1].getSubjectDistinguishedName(),
                  _root1_int1->getSubjectDistinguishedName());
        EXPECT_EQ(pemChain[2].getSubjectDistinguishedName(),
                  _root1_int1_cert1->getSubjectDistinguishedName());
    });
}

TEST_F(X509Test, testIfChainWithInvalidCharsFailsToLoad)
{
    EXPECT_THROW({
        auto pemChain = util::loadPEMChain(_pemChainInvalid);
    }, MoCOCrWException);
}

TEST_F(X509Test, testLoadEmptyChain)
{
    auto pemChain = util::loadPEMChain("");
    EXPECT_EQ(pemChain.size(), 0);
}

TEST_F(X509Test, testLoadSingleCertAsChainWorks)
{
    auto pemChain = util::loadPEMChain(_pemString);

    EXPECT_EQ(pemChain.size(), 1);
    EXPECT_EQ(pemChain[0].getSubjectDistinguishedName(), _cert.getSubjectDistinguishedName());
}

TEST_F(X509Test, testChainLoadFailsWithMissingCertEndMarker)
{
    auto cert = _pemString;
    cert.erase(cert.size()-3);
    EXPECT_THROW({
        auto pemChain = util::loadPEMChain(cert);
    }, MoCOCrWException);
}

TEST_F(X509Test, testChainLoadFailsWithEmptyCert)
{
    auto cert = "-----BEGIN CERTIFICATE-----\n   \n-----END CERTIFICATE-----"s;
    EXPECT_THROW({
        auto pemChain = util::loadPEMChain(cert);
    }, MoCOCrWException);
}

TEST_F(X509Test, testGetSerialNumber)
{
    EXPECT_THROW(_cert.getSerialNumber(), OpenSSLException)
        << "X509Certificate::getSerialNumber() should have thrown for serial numbers > sizeof(long)";
    EXPECT_EQ("17096587725777913388", _cert.getSerialNumberDecimal())
        << "X509Certificate::getSerialNumberDecimal() did not return expected value";
    EXPECT_EQ((std::vector<uint8_t>{0xed, 0x43, 0x47, 0xf4, 0x7a, 0x4b, 0xc6, 0x2c}),
              _cert.getSerialNumberBinary())
        << "X509Certificate::getSerialNumberBinary() did not return expected value";

    auto shortSerialCert = X509Certificate::fromPEM(_shortSerialPemString);
    EXPECT_EQ(12, shortSerialCert.getSerialNumber());
    EXPECT_EQ("12", shortSerialCert.getSerialNumberDecimal());
    EXPECT_EQ(std::vector<uint8_t>{0x0c}, shortSerialCert.getSerialNumberBinary());

    auto negativeSerialCert = X509Certificate::fromPEM(_negativeSerialPemString);
    EXPECT_THROW(negativeSerialCert.getSerialNumber(), OpenSSLException)
        << "X509Certificate::getSerialNumber() should have thrown for serial numbers < 0";
    EXPECT_EQ("-42", negativeSerialCert.getSerialNumberDecimal());
    EXPECT_EQ(std::vector<uint8_t>{0x2a}, negativeSerialCert.getSerialNumberBinary());
}

TEST_F(X509Test, testRootCertificateIsCA)
{
    EXPECT_TRUE(_root1->isCA())
        << "X509Certificate::isCA(): Root1 certificate is a CA";

    EXPECT_TRUE(_root2->isCA())
        << "X509Certificate::isCA(): Root2 certificate is a CA";

    EXPECT_TRUE(_eccRoot->isCA())
        << "X509Certificate::isCA(): EccRoot certificate is a CA";

}

TEST_F(X509Test, testIntermediateCertificateIsCA)
{
    std::unique_ptr<X509Certificate> _root2_int1 =
            std::make_unique<X509Certificate>(loadCertFromFile("root2.int1.pem"));

    EXPECT_TRUE(_root1_int1->isCA())
        << "X509Certificate::isCA(): Root1 Intermediate Certificate is a CA";

    EXPECT_TRUE(_root2_int1->isCA())
        << "X509Certificate::isCA(): Root2 Intermediate Certificate is a CA";

    EXPECT_TRUE(_eccIntermediate->isCA())
        << "X509Certificate::isCA(): eccIntermediate Intermediate Certificate is a CA";
}

TEST_F(X509Test, testClientCertificateIsNotCA)
{
    std::unique_ptr<X509Certificate> _root2_int1_cert1 =
            std::make_unique<X509Certificate>(loadCertFromFile("root2.int1.cert1.pem"));

    EXPECT_FALSE(_root1_int1_cert1->isCA())
        << "X509Certificate::isCA(): Root1 Client Certificate is not a CA";

    EXPECT_FALSE(_root2_int1_cert1->isCA())
        << "X509Certificate::isCA(): Root2 Client Certificate is not a CA";

    EXPECT_FALSE(_eccUser->isCA())
        << "X509Certificate::isCA(): eccUser Client Certificate is not a CA";
}

TEST_F(X509Test, testExpiredCertificateIsNotCA)
{
    std::unique_ptr<X509Certificate> expiredCAcert =
            std::make_unique<X509Certificate>(loadCertFromFile("expiredCA.pem"));
    /*Check an expired CA certificate*/
    EXPECT_TRUE(expiredCAcert->isCA())
        << "X509Certificate::isCA(): Certificate is a CA";
    /*Check an expired non CA certificate*/
    EXPECT_FALSE(_root1_expired->isCA())
        << "X509Certificate::isCA(): Certificate is not a CA";
}

TEST_F(X509Test, testGivenNameGetter)
{
    auto _given_name_cert = X509Certificate::fromPEM(_certWithGivenName);

    using ::testing::Eq;
    auto subject = _given_name_cert.getSubjectDistinguishedName();

    ASSERT_THAT(subject.commonName(), Eq("ImATeapot"));
    ASSERT_THAT(subject.countryName(), Eq("DE"));
    ASSERT_THAT(subject.localityName(), Eq("oben"));
    ASSERT_THAT(subject.stateOrProvinceName(), Eq("nebenan"));
    ASSERT_THAT(subject.organizationalUnitName(), Eq("LinuxSupport"));
    ASSERT_THAT(subject.organizationName(), Eq("LinuxAG"));
    ASSERT_THAT(subject.pkcs9EmailAddress(), Eq("support@example.com"));
    ASSERT_THAT(subject.serialNumber(), Eq("08E36DD501941432358AFE8256BC6EFD"));
    ASSERT_THAT(subject.givenName(), Eq("GivenName"));
}

