/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#include <fstream>
#include <algorithm>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

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

template<class T>
std::vector<T> bytesFromFile(const std::string &filename)
{
    static_assert(sizeof(T) == sizeof(char), "bytesFromFile only works with 1 byte data types");

    std::ifstream file{filename};
    if (!file.good()) {
        std::string errorMsg{"Cannot load certificate from file "};
        errorMsg = errorMsg + filename;
        throw std::runtime_error(errorMsg);
    }

    file.seekg(0, std::ios::end);
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<T> buffer;
    buffer.resize(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

template<class Res, Res(Func)(const std::string&)>
auto openSSLObjectFromFile(const std::string &filename)
{
    auto buffer = bytesFromFile<char>(filename);
    return Func({buffer.data(), buffer.size()});
}

X509Certificate loadCertFromFile(const std::string &filename)
{
    return openSSLObjectFromFile<X509Certificate, X509Certificate::fromPEM>(filename);
}

X509Certificate loadCertFromDERFile(const std::string &filename)
{
    auto buffer = bytesFromFile<uint8_t>(filename);
    return X509Certificate::fromDER(buffer);
}

AsymmetricPublicKey loadPubkeyFromFile(const std::string &filename)
{
    return openSSLObjectFromFile<AsymmetricPublicKey,
        AsymmetricPublicKey::readPublicKeyFromPEM>(filename);
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

    X509Certificate _cert = X509Certificate::fromPEM(_pemString);

    std::unique_ptr<X509Certificate> _root1;
    std::unique_ptr<X509Certificate> _root1_cert1;
    std::unique_ptr<X509Certificate> _root1_future;
    std::unique_ptr<X509Certificate> _root1_expired;
    std::unique_ptr<X509Certificate> _root1_int1;
    std::unique_ptr<X509Certificate> _root1_int1_cert1;
    std::unique_ptr<X509Certificate> _root1_int1_int11;
    std::unique_ptr<X509Certificate> _root1_int1_int11_cert1;
    std::unique_ptr<X509Certificate> _root1_int1_int11_cert2;
    std::unique_ptr<X509Certificate> _root1_int2;
    std::unique_ptr<X509Certificate> _root1_int2_int21;
    std::unique_ptr<X509Certificate> _root1_int2_int21_cert1;

    std::unique_ptr<X509Certificate> _root2;
    std::unique_ptr<X509Certificate> _root2_int1;
    std::unique_ptr<X509Certificate> _root2_int1_cert1;

    std::unique_ptr<X509Certificate> _year1970;
    std::unique_ptr<X509Certificate> _year2049;
    std::unique_ptr<X509Certificate> _year2050;
    std::unique_ptr<X509Certificate> _year9999;

    std::unique_ptr<AsymmetricPublicKey> _root1_pubkey;
};

void X509Test::SetUp()
{
    _cert = X509Certificate::fromPEM(_pemString);

    _root1 = std::make_unique<X509Certificate>(loadCertFromFile("root1.pem"));
    _root1_cert1 = std::make_unique<X509Certificate>(loadCertFromFile("root1.cert1.pem"));
    _root1_future = std::make_unique<X509Certificate>(loadCertFromFile("root1.future.pem"));
    _root1_expired = std::make_unique<X509Certificate>(loadCertFromFile("root1.expired.pem"));
    _root1_int1 = std::make_unique<X509Certificate>(loadCertFromFile("root1.int1.pem"));
    _root1_int1_cert1 = std::make_unique<X509Certificate>(loadCertFromFile("root1.int1.cert1.pem"));
    _root1_int1_int11 = std::make_unique<X509Certificate>(loadCertFromFile("root1.int1.int11.pem"));
    _root1_int1_int11_cert1 =
        std::make_unique<X509Certificate>(loadCertFromFile("root1.int1.int11.cert1.pem"));
    _root1_int1_int11_cert2 =
        std::make_unique<X509Certificate>(loadCertFromFile("root1.int1.int11.cert2.pem"));
    _root1_int2 = std::make_unique<X509Certificate>(loadCertFromFile("root1.int2.pem"));
    _root1_int2_int21 = std::make_unique<X509Certificate>(loadCertFromFile("root1.int2.int21.pem"));
    _root1_int2_int21_cert1 =
        std::make_unique<X509Certificate>(loadCertFromFile("root1.int2.int21.cert1.pem"));

    _root2 = std::make_unique<X509Certificate>(loadCertFromFile("root2.pem"));
    _root2_int1 = std::make_unique<X509Certificate>(loadCertFromFile("root2.int1.pem"));
    _root2_int1_cert1 = std::make_unique<X509Certificate>(loadCertFromFile("root2.int1.cert1.pem"));

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
}

const std::string X509Test::_pemString{
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDijCCAnICCQDLbB6fOKuKUjANBgkqhkiG9w0BAQsFADBHMQswCQYDVQQGEwJk\n"
        "ZTELMAkGA1UECAwCYncxDDAKBgNVBAcMA3VsbTEMMAoGA1UECgwDQk1XMQ8wDQYD\n"
        "VQQLDAZDYXIgSVQwHhcNMTcwMzA5MDkxOTI4WhcNMTcxMTIwMDkxOTI4WjCBxjES\n"
        "MBAGA1UEAwwJSW1BVGVhcG90MQswCQYDVQQGEwJERTENMAsGA1UEBwwEb2JlbjEQ\n"
        "MA4GA1UECAwHbmViZW5hbjEWMBQGA1UECwwNTGludXggU3VwcG9ydDEMMAoGA1UE\n"
        "CgwDQk1XMSkwJwYJKoZIhvcNAQkBFhpzdXBwb3J0QGxpbnV4LmJtd2dyb3VwLmNv\n"
        "bTExMC8GA1UEBRMoRUNVLVVJRDowOEUzNkRENTAxOTQxNDMyMzU4QUZFODI1NkJD\n"
        "NkVGRDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL+7+KU8KW3lV9W3\n"
        "keTv2/6nWsVhtOCdsM0q+8Z1ttZ+jh0R2Ki2hqKFfxd91uhSjRunRu7LUvWaDnW0\n"
        "1trNvwyyAPIC33r8JwmBk4y6R0tYrw4JE4fEsQpSyjtsi9OOeG9yJbO9EDSjEgfU\n"
        "H4vjgiBQolnTr5OetNB4doJ+lAIUTU9j8woqVr1Y7hqDoW2S9vs6z658QIseSGqB\n"
        "BG1ZuJkCO+VTjdSETPgQWnWlOl9aS+utyvT/CLH8MvBmkpMV8D8P0adpT6AB3NQY\n"
        "iK6EuFRzGAJtCFWF+iL2pyhEKb0gaM7Bb7UROxo+BVUc5w1WWZWpm9X6F5LGTnLt\n"
        "S9fxZccCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEADu1VAiSfn5DTyymTWIByDJgd\n"
        "F9czFPRqyPL3kK3SpMQDqj8uuTYYbgPWP5PPUp2qzazubSWEK3sgu08pM9F/oBJS\n"
        "XXT/FbrfR38LG+hHer6hqBNmN4+mlifdiNCguqEowouAQfduGfGHzNdrUlt0svIs\n"
        "b4Jv7NXsn4pBx6ObGfYWNlxD1zwt71pdjVdwUQqJIEVihh0Bwv4wSmqFJ/iWJdpY\n"
        "0v1OLbCDbbOXPLx/fWyf0TN3bt/Fr1OlGY4UCnKxi+sjTRzWHcmQ2Ox6DgI9MOMZ\n"
        "o7k8jBD0+ZUfE2t9tXJuTKSldE7TuK9ff3NFc433s3FVNPqSE59qs+pJW5joLA==\n"
        "-----END CERTIFICATE-----\n"};

const std::string X509Test::_shortSerialPemString{
        "-----BEGIN CERTIFICATE-----\n"
        "MIICOTCCAeOgAwIBAgIBDDANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJERTEb\n"
        "MBkGA1UECAwSQmFkZW4tV3VlcnR0ZW1iZXJnMQwwCgYDVQQHDANVbG0xGDAWBgNV\n"
        "BAoMD0JNVyBDYXIgSVQgR21iSDENMAsGA1UECwwESkMtNzEZMBcGA1UEAwwQVGVz\n"
        "dCBDZXJ0aWZpY2F0ZTAeFw0xNzA3MjUxMjAyNTJaFw0xODA3MjUxMjAyNTJaMHwx\n"
        "CzAJBgNVBAYTAkRFMRswGQYDVQQIDBJCYWRlbi1XdWVydHRlbWJlcmcxDDAKBgNV\n"
        "BAcMA1VsbTEYMBYGA1UECgwPQk1XIENhciBJVCBHbWJIMQ0wCwYDVQQLDARKQy03\n"
        "MRkwFwYDVQQDDBBUZXN0IENlcnRpZmljYXRlMFwwDQYJKoZIhvcNAQEBBQADSwAw\n"
        "SAJBAPBv9TuHRI+t28ONKkKspleukIcGmHx/zDBpoPYRUU5VzT3nNPLbxD2MOxfI\n"
        "Tv6r+8ielFOrnabK/6LcLadin20CAwEAAaNQME4wHQYDVR0OBBYEFBBwzzzDSMfC\n"
        "uuL/aoaa9HwgPUefMB8GA1UdIwQYMBaAFBBwzzzDSMfCuuL/aoaa9HwgPUefMAwG\n"
        "A1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADQQBFBuE9h4TrimeKhqbCPEmkUlX0\n"
        "cS0ri/kzH2BN2lM1Jt+NdPeMTGnkIiLwPoIaPSFeTZjz5Ka0mpq2wClzk2Ci\n"
        "-----END CERTIFICATE-----\n"};

const std::string X509Test::_negativeSerialPemString{
        "-----BEGIN CERTIFICATE-----\n"
        "MIICQzCCAe2gAwIBAgIB1jANBgkqhkiG9w0BAQsFADCBgDELMAkGA1UEBhMCREUx\n"
        "GzAZBgNVBAgMEkJhZGVuLVd1ZXJ0dGVtYmVyZzEMMAoGA1UEBwwDVWxtMRgwFgYD\n"
        "VQQKDA9CTVcgQ2FyIElUIEdtYkgxDTALBgNVBAsMBEpDLTcxHTAbBgNVBAMMFE5l\n"
        "Z2F0aXZlIFNlcmlhbCBUZXN0MB4XDTE3MDcyNTEyMTE1NVoXDTE4MDcyNTEyMTE1\n"
        "NVowgYAxCzAJBgNVBAYTAkRFMRswGQYDVQQIDBJCYWRlbi1XdWVydHRlbWJlcmcx\n"
        "DDAKBgNVBAcMA1VsbTEYMBYGA1UECgwPQk1XIENhciBJVCBHbWJIMQ0wCwYDVQQL\n"
        "DARKQy03MR0wGwYDVQQDDBROZWdhdGl2ZSBTZXJpYWwgVGVzdDBcMA0GCSqGSIb3\n"
        "DQEBAQUAA0sAMEgCQQDXKboXa5QW0I7JknewmLQqRTOp0QcDsrck3THEeaSBRNyb\n"
        "04uQFZGftdsuC2b9jr1k8NCiuy3Su81tn4ku1dIPAgMBAAGjUDBOMB0GA1UdDgQW\n"
        "BBRu6KAISE1V4jhYuiyb3iEZTf2ijDAfBgNVHSMEGDAWgBRu6KAISE1V4jhYuiyb\n"
        "3iEZTf2ijDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA0EAENPsu/If+1Ir\n"
        "YMjWHTmu7K7pwJxYg8QBdfhVbnc5qHK+sZk1zHh+ng7bW1QZIvitKhW8hnUiwz3O\n"
        "wvM4cGGE+Q==\n"
        "-----END CERTIFICATE-----\n"};

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
-----END CERTIFICATE-----)"};

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
-----END CERTIFICATE-----)"};

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
    ASSERT_THAT(subject.organizationName(), Eq("BMW"));
    ASSERT_THAT(subject.pkcs9EmailAddress(), Eq("support@linux.bmwgroup.com"));
    ASSERT_THAT(subject.serialNumber(), Eq("ECU-UID:08E36DD501941432358AFE8256BC6EFD"));
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

TEST_F(X509Test, testSimpleCertValidation)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_NO_THROW(_root1_cert1->verify(trustStore, intermediateCAs));
}

TEST_F(X509Test, testExpiredCertValidationFails)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_THROW(_root1_expired->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(X509Test, testFutureCertValidationFails)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_THROW(_root1_future->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(X509Test, testSimpleCertValidationWorksForSubCA)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_NO_THROW(_root1_int1->verify(trustStore, intermediateCAs));
}

TEST_F(X509Test, testVerificationsFailsWithEmptyTrustRoot)
{
    std::vector<X509Certificate> trustStore{};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_THROW(_root1_cert1->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(X509Test, testVerificationWorksWithIntermediateInTruststore)
{
    std::vector<X509Certificate> trustStore{*_root1_int1.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_NO_THROW(_root1_int1_cert1->verify(trustStore, intermediateCAs));
}

TEST_F(X509Test, testChainVerificationLen1Works)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int1.get()};

    ASSERT_NO_THROW(_root1_int1_cert1->verify(trustStore, intermediateCAs));
}

TEST_F(X509Test, testChainVerificationFailsWithWrongIntermediate)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int2.get()};

    ASSERT_THROW(_root1_int1_cert1->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(X509Test, testVerficationsFailsWithEmptyTruststoreButRootAsIntermediate)
{
    std::vector<X509Certificate> trustStore{};
    std::vector<X509Certificate> intermediateCAs{*_root1.get()};

    ASSERT_THROW(_root1_cert1->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(X509Test, testVerificationFailsForTheRootCAWhenTruststoreIsEmpty)
{
    std::vector<X509Certificate> trustStore{};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_THROW(_root1->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(X509Test, testChainVerificationLen2Works)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int1.get(), *_root1_int1_int11.get()};

    ASSERT_NO_THROW(_root1_int1_int11_cert1->verify(trustStore, intermediateCAs));
    ASSERT_NO_THROW(_root1_int1_int11_cert2->verify(trustStore, intermediateCAs));
}

TEST_F(X509Test, testChainVerificationLen2WorksWithOtherOrderForIntermediates)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int1_int11.get(), *_root1_int1.get()};

    ASSERT_NO_THROW(_root1_int1_int11_cert1->verify(trustStore, intermediateCAs));
}

/* We want to see that the verifcation respects the path len constraint in CA certificates
 * Towards this purpose we wake _root1_int2 which has a pathlen of 0.
 * This means that it can issue certificates but these certificates can
 * not be used to sign themselves again.
 * For testing purposes, _root1_int2_int21 is a certificate with CA flag. We used it to sign
 * _root1_int2_int21_cert1. However, this cert violates the path len constraint of root1_int2.
 * Consequently, verification should fail here.
 */
TEST_F(X509Test, testIfCAPathLenIsRespected)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int2.get(), *_root1_int2_int21.get()};

    ASSERT_THROW(_root1_int2_int21_cert1->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(X509Test, testCompleteChainVerificationFailsWithWrongRoot)
{
    std::vector<X509Certificate> trustStore{*_root2.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1.get(), *_root1_int1.get(), *_root1_int1_int11.get()};

    ASSERT_THROW(_root1_int1_int11_cert1->verify(trustStore, intermediateCAs), MoCOCrWException);
}

TEST_F(X509Test, testOpenSSLPartialVerificationWithIntermediateInTruststoreWorks)
{
    std::vector<X509Certificate> trustStore{*_root1_int1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int1_int11.get()};

    ASSERT_NO_THROW(_root1_int1_int11_cert1->verify(trustStore, intermediateCAs));
}

TEST_F(X509Test, testVerificationWorksWithUnusedElementsInChainParam)
{
    std::vector<X509Certificate> trustStore{*_root1.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int1_int11.get(), *_root1_int1.get(),
                                                 *_root1_int2.get()};

    ASSERT_NO_THROW(_root1_int1_int11_cert1->verify(trustStore, intermediateCAs));
}

TEST_F(X509Test, testVerificationWorksWithBothRootsInTruststore)
{
    std::vector<X509Certificate> trustStore{*_root1.get(), *_root2.get()};
    std::vector<X509Certificate> intermediateCAs{};

    ASSERT_NO_THROW(_root1_int1->verify(trustStore, intermediateCAs));
    ASSERT_NO_THROW(_root2_int1->verify(trustStore, intermediateCAs));
}

/*
 * We want to see if we can use verification for two roots and different chains
 * if we put all the necessary information in truststore and intermediates.
 */
TEST_F(X509Test, testVerificationWorksWithBothRootsInTrustStoreComplexChains)
{
    std::vector<X509Certificate> trustStore{*_root1.get(), *_root2.get()};
    std::vector<X509Certificate> intermediateCAs{*_root1_int1.get(), *_root2_int1.get()};

    ASSERT_NO_THROW(_root1_int1_cert1->verify(trustStore, intermediateCAs));
    ASSERT_NO_THROW(_root2_int1_cert1->verify(trustStore, intermediateCAs));
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
}

TEST_F(X509Test, testIfPubkeyDoesNotMatchOtherCertificate)
{
    EXPECT_NE(_root2->getPublicKey(), *_root1_pubkey);
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
    EXPECT_EQ("14658124556383521362", _cert.getSerialNumberDecimal())
        << "X509Certificate::getSerialNumberDecimal() did not return expected value";
    EXPECT_EQ((std::vector<uint8_t>{0xcb, 0x6c, 0x1e, 0x9f, 0x38, 0xab, 0x8a, 0x52}),
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
