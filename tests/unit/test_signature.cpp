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
#include <algorithm>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/evp.h>

#include "IOUtils.h"

#include "signature.cpp"

using namespace std::string_literals;

using namespace mococrw;

class SignatureTest : public ::testing::Test
{
public:
    void SetUp() override;

protected:
    std::unique_ptr<AsymmetricKeypair> _keyPairRsa;
    std::unique_ptr<AsymmetricKeypair> _keyPairEcc;

    std::unique_ptr<AsymmetricPublicKey> _root1_RsaPubkey;
    std::unique_ptr<X509Certificate> _root1_RsaCert;

    /* The SHA256 digest of the test message. */
    static const std::vector<uint8_t> _testMessageDigestSHA256;
    /* The SHA512 digest of the test message. */
    static const std::vector<uint8_t> _testMessageDigestSHA512;
    /* The SHA1 digest of the test message. */
    static const std::vector<uint8_t> _testMessageDigestSHA1;

    /* Valid RSA keys belonging to the same key pair. */
    static const std::string _validRsaPublicKey;
    static const std::string _validRsaPrivateKey;

    /* Valid ECC PRIME_256v1 keys belonging to the same key pair. */
    static const std::string _validEccPublicKey;
    static const std::string _invalidEccPublicKey;

    /*
     * Unused for the time being. To be kept for future reference (matches _validEccPublicKey and
     * _validEccCertificate
     */
    static const std::string _validEccPrivateKey;

    /* Valid ECC certificate */
    static const std::string _validEccCertificate;

    /* The signatures of the hashed test message with the previously declared private key */
    static const std::vector<uint8_t> _validPKCS1SignatureSHA256;
    static const std::vector<uint8_t> _validPKCS1SignatureSHA512;
    static const std::vector<uint8_t> _validEccSignatureSHA1;

    /* Pre-configured padding modes for RSA operations */
    static const PKCSPadding sha256PKCSPadding;
    static const PKCSPadding sha512PKCSPadding;
    static const PSSPadding sha256PSSPadding;
    static const PSSPadding sha512PSSPadding;
};

void SignatureTest::SetUp()
{
    _keyPairRsa = std::make_unique<AsymmetricKeypair>(mococrw::AsymmetricKeypair::generateRSA());
    _keyPairEcc = std::make_unique<AsymmetricKeypair>(mococrw::AsymmetricKeypair::generateECC());
}

const PKCSPadding SignatureTest::sha256PKCSPadding{DigestTypes::SHA256};
const PKCSPadding SignatureTest::sha512PKCSPadding{DigestTypes::SHA512};
const PSSPadding SignatureTest::sha256PSSPadding{DigestTypes::SHA256};
const PSSPadding SignatureTest::sha512PSSPadding{DigestTypes::SHA512};

const std::string SignatureTest::_validEccCertificate{
R"(-----BEGIN CERTIFICATE-----
MIICjzCCAjWgAwIBAgIBADAKBggqhkjOPQQDAjCBvDESMBAGA1UEAwwJSW1BVGVh
cG90MQswCQYDVQQGEwJERTENMAsGA1UEBwwEb2JlbjEQMA4GA1UECAwHbmViZW5h
bjEWMBQGA1UECwwNTGludXggU3VwcG9ydDERMA8GA1UECgwITGludXggQUcxIjAg
BgkqhkiG9w0BCQEWE3N1cHBvcnRAZXhhbXBsZS5jb20xKTAnBgNVBAUTIDA4RTM2
REQ1MDE5NDE0MzIzNThBRkU4MjU2QkM2RUZEMB4XDTE4MTEyNzE3MjUyN1oXDTE4
MTEyNzE3MjcyN1owgbwxEjAQBgNVBAMMCUltQVRlYXBvdDELMAkGA1UEBhMCREUx
DTALBgNVBAcMBG9iZW4xEDAOBgNVBAgMB25lYmVuYW4xFjAUBgNVBAsMDUxpbnV4
IFN1cHBvcnQxETAPBgNVBAoMCExpbnV4IEFHMSIwIAYJKoZIhvcNAQkBFhNzdXBw
b3J0QGV4YW1wbGUuY29tMSkwJwYDVQQFEyAwOEUzNkRENTAxOTQxNDMyMzU4QUZF
ODI1NkJDNkVGRDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKGWituJ9NwjpXXQ
FkpS4I4TdtAF7TGGTgQw+YZbtnih2kYRWUY19nSL/6hbDpWsGklNMJIjDqEaQwn1
7sX4PkWjJjAkMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEBMAoG
CCqGSM49BAMCA0gAMEUCIDFaFwDfQ3wy8L51WqpwYeA5IQkn8sMXJ6zrhntWUYfX
AiEApz/8/0+5CjFNIhfdNqJrDvGE4R7sf0yphQ/0NnLO/44=
-----END CERTIFICATE-----)"};

const std::string SignatureTest::_validRsaPublicKey{
R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp3YVsDAXbXXafN19SliI
evUMvQyk4bdCL/UUNzED/esA68NKr0C7IO7+wG04mdV8HoMTmXevcNyu7Gfk6nBW
BIOb1JazvyfloxmpDK602/WEzDP6AMCY3jk6nB3nYP4ydxH/lwiYwfnpnFlp+8C/
zgqROmbYyQi83DXJZlVjZWr+UZfyvoF4geRkiTd41epjSxR9A7eK3lQ3d0OnD09c
rtrq3QTVf/i+Rrw7czc2j88vbYJAnd2MyuLI4dbiOoEAvdp3O5oqFBIC0SrNMpE/
gIozEnABGPQyClIeOlxJrydGnwUAxL8SA83MNyxT4B3+WByXsJf2oC05CsZxvFwF
NQIDAQAB
-----END PUBLIC KEY-----)"};

const std::string SignatureTest::_validEccPublicKey{
R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoZaK24n03COlddAWSlLgjhN20AXt
MYZOBDD5hlu2eKHaRhFZRjX2dIv/qFsOlawaSU0wkiMOoRpDCfXuxfg+RQ==
-----END PUBLIC KEY-----)"};

const std::string SignatureTest::_invalidEccPublicKey{
R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEokMAQr8qdmAzAuI8lqnhkO+R3gxM
qfdiYjxBqRq225MTwfCqc46ksOCKyonMzUmcHfY1EzrdOEib+6FWGyeE5w==
-----END PUBLIC KEY-----)"};

const std::string SignatureTest::_validRsaPrivateKey{
R"(-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCndhWwMBdtddp8
3X1KWIh69Qy9DKTht0Iv9RQ3MQP96wDrw0qvQLsg7v7AbTiZ1XwegxOZd69w3K7s
Z+TqcFYEg5vUlrO/J+WjGakMrrTb9YTMM/oAwJjeOTqcHedg/jJ3Ef+XCJjB+emc
WWn7wL/OCpE6ZtjJCLzcNclmVWNlav5Rl/K+gXiB5GSJN3jV6mNLFH0Dt4reVDd3
Q6cPT1yu2urdBNV/+L5GvDtzNzaPzy9tgkCd3YzK4sjh1uI6gQC92nc7mioUEgLR
Ks0ykT+AijMScAEY9DIKUh46XEmvJ0afBQDEvxIDzcw3LFPgHf5YHJewl/agLTkK
xnG8XAU1AgMBAAECggEATVNzlFXAm6TN7NaBojDbZJt+9FTAVhG/GFH8sbeKdldr
p3IYLHCheAWj0MseVbqEg7pW9IiVlHHyu+sFg1O4BIGZFUM5YM1VdkjFDLwne2IV
ng1qJarJa+PVMn2Ed/8o4l6HPQCVOQzjWHTZQYyxhLzQbr1K4RmNy8lyZDSNnyhX
Er3FGU3E3lvoaBEOo2Kznu51GwZH2kqWZdYVe9For27Y3mf9uqKdkkG6Y/yV+5TN
YKiKMYKYtA5MW4kHOxRqVgJDFx8xmfYbTfIkKKYgcO5WtO+xcS0kg1+1Gnox6xrD
fCgALgERorKzgybwgEBGkIrexnFQYTmvW7a/+7W9iQKBgQDb53A4SdCHFI0r3Iue
X7lmQn5oE06a/yAanGVSBE3SjC3vT7HUQsBoKZ7YH1PMppwg9pqHzNpBwneJ5tz/
5h9RtKCeO9MqCx0Fbt+GxhTi99JnuGlCoWeMHHmKCQ09Kt9f7Uu9pmYMrTuNTQkL
8KC8fT/cAGWqvvzauX3R5vV6FwKBgQDC8vRQKYNcsSDSFBWOhqANcq8fGEarNcpy
w/1zqsOCt8Ti8Px6+3hjvjSlYatClwjaRjJCauI2/tFDdx2GmClmQ6RTckyNR/t+
K5U+YW9xb9cullJrSUnFNTDxOmZxw/Dh2P8vaHEmd6UXdgCq9/4weOgTGN99AfGC
fscYgySmkwKBgQDH6nO++Hw3EZv10B6t8GBgcvrwKv0/M8k/6AbEtVz6mK357f3A
9p5tE8lwuao5Vw6BeS+rXbTeK6j5GYS4r8CxSwDqWYDzq/7KPa3AnLvIS3xhBunK
xWmZmxlzQB9lCGDimJxO4cPMqoCFSQ98Z1n5gfRYUZQb0l2ViySzesCYKQKBgBHy
8I+Y4uFb5ZuyAbIXrxDN6FXClG8bCsK6TNGjfVDBvrzuVzCziogUcSBw96Wv5j7C
i8oVsTJDD91YUD2eMOGbhLuyIF45rGwXcyxFKE+XboZ5jKkYHFSt6w2qxNfgpIMG
yagBw7k49thMIw+auaqY1zU66wjFbwkGxyn4mR1FAoGBAKDnwWHgIVHFjI1wf/Vu
r7/HRKKAqTfz8m5F/LmmmMfDB1LpNtWtyNVBZzLCDuCNqTuxIIl8eWWpTQu5uYfV
I81xKRx2By82a1Py9gzQAozGmMtwV8CornxwU2wbUmoiADStDouzr/wqlOFo780O
5xWdBSm554PdnwbLVRUxX3aP
-----END PRIVATE KEY-----)"};

const std::string SignatureTest::_validEccPrivateKey{
R"(-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg+g/5RMyEkKBwEtdk
a29Ix3qgyrGBjpRnMBPvELa/jHWhRANCAAShlorbifTcI6V10BZKUuCOE3bQBe0x
hk4EMPmGW7Z4odpGEVlGNfZ0i/+oWw6VrBpJTTCSIw6hGkMJ9e7F+D5F
-----END PRIVATE KEY-----)"};

const std::vector<uint8_t> SignatureTest::_validPKCS1SignatureSHA256{
        0x16, 0x00, 0x22, 0xD8, 0x72, 0x91, 0x6F, 0xD6, 0x24, 0x0C, 0xBD, 0x1C, 0xDE, 0x25, 0x4C,
        0x8E, 0x9F, 0x8D, 0x55, 0xAA, 0xE7, 0x1A, 0x10, 0xE0, 0x56, 0x67, 0x5D, 0x5C, 0xD8, 0x0A,
        0x0B, 0x58, 0x35, 0xA6, 0x5B, 0x77, 0x05, 0x80, 0x4D, 0x8E, 0xDE, 0xCC, 0x65, 0x7A, 0xDB,
        0xB0, 0x46, 0x72, 0x3C, 0x41, 0x38, 0xA4, 0xE7, 0x75, 0x4C, 0x84, 0x5D, 0x6D, 0xD2, 0x3C,
        0xBD, 0x39, 0x61, 0x16, 0x66, 0xCA, 0x0E, 0xA1, 0xB2, 0x51, 0xA6, 0x30, 0xD2, 0x69, 0xFD,
        0x25, 0xB1, 0x85, 0x66, 0x7D, 0x2C, 0x7B, 0x83, 0xA2, 0x45, 0xD6, 0x51, 0xED, 0xD1, 0x43,
        0x22, 0x61, 0x3A, 0xE3, 0x03, 0xE8, 0xD2, 0x90, 0x39, 0xB1, 0xD0, 0xDB, 0x3B, 0x9F, 0xB6,
        0x4F, 0x9F, 0x5E, 0x27, 0x8C, 0x63, 0x33, 0x56, 0xD1, 0x65, 0xB4, 0x1B, 0x64, 0x1C, 0xE8,
        0x08, 0xD9, 0x20, 0x78, 0xF7, 0xE0, 0x65, 0x69, 0xE6, 0x3E, 0x74, 0xE6, 0x5D, 0x74, 0x8E,
        0xA6, 0xB8, 0x46, 0x90, 0x4E, 0x3B, 0x33, 0x28, 0x81, 0xCF, 0x85, 0x32, 0x3C, 0x69, 0xF6,
        0x66, 0x25, 0xA0, 0x93, 0x9C, 0x7C, 0xC1, 0x2A, 0xBB, 0xAA, 0x7E, 0xDE, 0xBB, 0xC0, 0x9A,
        0x38, 0x4A, 0x2B, 0xB3, 0xFE, 0xD5, 0xCB, 0xB3, 0x4A, 0x2A, 0xDD, 0x13, 0x8D, 0xB8, 0x79,
        0x80, 0xC3, 0xDB, 0x18, 0x86, 0xEB, 0xEC, 0x0A, 0xBD, 0x7C, 0x9C, 0xE9, 0x6A, 0x1E, 0x87,
        0x76, 0xF7, 0xC4, 0x0D, 0x53, 0x6F, 0xD8, 0x09, 0x6C, 0xE7, 0x01, 0x11, 0xC1, 0x7B, 0x84,
        0xA1, 0x7C, 0x64, 0xE2, 0x88, 0xF1, 0x01, 0x76, 0x93, 0x38, 0x47, 0xC0, 0x10, 0x33, 0x9B,
        0x22, 0x43, 0x14, 0xBE, 0x6E, 0xD5, 0x9A, 0x0E, 0x55, 0x90, 0x6D, 0x29, 0xD9, 0x54, 0xAA,
        0x18, 0x37, 0xE1, 0x83, 0xFF, 0x28, 0x46, 0x31, 0x35, 0xA8, 0x00, 0x23, 0x79, 0x0F, 0x83,
        0x0D};

const std::vector<uint8_t> SignatureTest::_validEccSignatureSHA1{
        0x30, 0x44, 0x02, 0x20, 0x4e, 0x18, 0x49, 0xf8, 0x21, 0x89, 0x86, 0x8a, 0xfc, 0x2f, 0xbc,
        0x4a, 0xba, 0xde, 0x9d, 0x96, 0x9c, 0xd9, 0xa0, 0x34, 0x6d, 0x86, 0x7d, 0xc8, 0xc1, 0x1b,
        0x35, 0xac, 0xe5, 0xcd, 0x39, 0x12, 0x02, 0x20, 0x73, 0xf0, 0xa6, 0x61, 0x85, 0xaa, 0xd3,
        0xcf, 0xfe, 0x3d, 0x58, 0xeb, 0xbb, 0x2f, 0xef, 0xbd, 0x2e, 0x3d, 0x23, 0xb5, 0x7e, 0x1b,
        0x7c, 0xee, 0xbd, 0x3d, 0x64, 0xac, 0x11, 0x09, 0x84, 0x44};

const std::vector<uint8_t> SignatureTest::_validPKCS1SignatureSHA512{
        0x77, 0x10, 0x46, 0xCC, 0xDF, 0xCC, 0x45, 0xD7, 0xEF, 0xE0, 0xC6, 0x19, 0xF4, 0xD1, 0x4C,
        0xC9, 0x55, 0x31, 0xC5, 0x4B, 0xEB, 0x82, 0xC3, 0xC8, 0x89, 0x1D, 0x33, 0x24, 0xE8, 0xDA,
        0x0F, 0x40, 0x01, 0xC7, 0x8C, 0x1D, 0x25, 0x84, 0x6E, 0x46, 0x7C, 0xBB, 0x0E, 0xAA, 0x24,
        0xAF, 0x86, 0xBC, 0x3A, 0xB7, 0x98, 0x32, 0x71, 0x17, 0xC4, 0x45, 0xD7, 0x06, 0xF5, 0x30,
        0xAF, 0x7D, 0x50, 0xA4, 0xA1, 0xC5, 0x67, 0x71, 0x17, 0x7D, 0xF1, 0x0D, 0xC1, 0xEA, 0x02,
        0x69, 0x6C, 0x46, 0x70, 0x4A, 0x88, 0x16, 0x8C, 0xF5, 0xEB, 0xAB, 0x74, 0x3F, 0x6E, 0x99,
        0x15, 0x37, 0x60, 0x2D, 0x6A, 0xA1, 0x03, 0x55, 0x31, 0x3B, 0x3A, 0xA4, 0xB2, 0x38, 0x16,
        0xC1, 0xDC, 0xDF, 0xB9, 0xAF, 0x56, 0x1D, 0xCB, 0xE9, 0xAC, 0x46, 0x9A, 0xA7, 0x48, 0x04,
        0x5C, 0x2D, 0x15, 0x04, 0x76, 0x26, 0xDE, 0xB2, 0x89, 0xDC, 0x06, 0xF5, 0xAF, 0xA6, 0x6F,
        0xDD, 0x72, 0x05, 0x8F, 0x12, 0xFF, 0x6A, 0x6A, 0x5C, 0x2E, 0xAD, 0x09, 0xAD, 0xCD, 0x20,
        0x68, 0x8B, 0x7C, 0xC8, 0x98, 0x30, 0xB1, 0x0F, 0xA1, 0x73, 0x75, 0x92, 0xDB, 0x32, 0x32,
        0x82, 0x7A, 0x5A, 0x65, 0x46, 0x49, 0xE1, 0x8D, 0x23, 0xB9, 0x2E, 0x99, 0xA4, 0xEA, 0x57,
        0x5F, 0x1F, 0x6A, 0xC7, 0x56, 0x3E, 0x5C, 0x04, 0x44, 0xCC, 0xB0, 0x66, 0xB1, 0x6E, 0xB1,
        0x33, 0x09, 0x4F, 0x52, 0x03, 0x78, 0x56, 0x12, 0x28, 0x2D, 0xD5, 0x38, 0x3F, 0x48, 0x8F,
        0xC8, 0x64, 0x8B, 0xEA, 0xD6, 0xFF, 0xD1, 0xEF, 0xD3, 0xE7, 0x10, 0x48, 0xF3, 0x44, 0x3E,
        0x48, 0x6A, 0xCE, 0xC4, 0xD0, 0x0A, 0x26, 0x38, 0x17, 0xFE, 0x3D, 0x7B, 0xBE, 0x82, 0x83,
        0xFE, 0x98, 0x59, 0x01, 0x35, 0xBB, 0xB6, 0x60, 0xF7, 0xAA, 0x0E, 0x90, 0xF7, 0xDE, 0xA6,
        0xAA};
/*
 * All of the _testMessageDigest* variables contain the hashed "Hello World!" string
 */
const std::vector<uint8_t> SignatureTest::_testMessageDigestSHA256{
        0x7F, 0x83, 0xB1, 0x65, 0x7F, 0xF1, 0xFC, 0x53, 0xB9, 0x2D, 0xC1, 0x81, 0x48, 0xA1, 0xD6,
        0x5D, 0xFC, 0x2D, 0x4B, 0x1F, 0xA3, 0xD6, 0x77, 0x28, 0x4A, 0xDD, 0xD2, 0x00, 0x12, 0x6D,
        0x90, 0x69};

const std::vector<uint8_t> SignatureTest::_testMessageDigestSHA512{
        0x86, 0x18, 0x44, 0xD6, 0x70, 0x4E, 0x85, 0x73, 0xFE, 0xC3, 0x4D, 0x96, 0x7E, 0x20, 0xBC,
        0xFE, 0xF3, 0xD4, 0x24, 0xCF, 0x48, 0xBE, 0x04, 0xE6, 0xDC, 0x08, 0xF2, 0xBD, 0x58, 0xC7,
        0x29, 0x74, 0x33, 0x71, 0x01, 0x5E, 0xAD, 0x89, 0x1C, 0xC3, 0xCF, 0x1C, 0x9D, 0x34, 0xB4,
        0x92, 0x64, 0xB5, 0x10, 0x75, 0x1B, 0x1F, 0xF9, 0xE5, 0x37, 0x93, 0x7B, 0xC4, 0x6B, 0x5D,
        0x6F, 0xF4, 0xEC, 0xC8};

const std::vector<uint8_t> SignatureTest::_testMessageDigestSHA1{
        0x2e, 0xf7, 0xbd, 0xe6, 0x08, 0xce, 0x54, 0x04, 0xe9, 0x7d, 0x5f, 0x04, 0x2f, 0x95, 0xf8,
        0x9f, 0x1c, 0x23, 0x28, 0x71};

/**
 * @brief Tests whether the interface that requires a key, a message digest and a padding mode
 * for creating a signature is outputing the correct PKCS1 signature by comparing it to a result
 * known to be correct.
 * - SHA256 hashing
 * - SHA512 hashing
 */
TEST_F(SignatureTest, testSuccessfulRsaSignatureOfMessageDigestPKCS1ComparedToKnownOutput)
{
    std::vector<uint8_t> signature;
    auto key = mococrw::AsymmetricKeypair::readPrivateKeyFromPEM(_validRsaPrivateKey, "");

    EXPECT_NO_THROW(signature
                            = SignatureUtils::RSA::create(key, sha256PKCSPadding, _testMessageDigestSHA256));
    EXPECT_EQ(_validPKCS1SignatureSHA256, signature);
    EXPECT_NO_THROW(signature
                            = SignatureUtils::RSA::create(key, sha512PKCSPadding, _testMessageDigestSHA512));
    EXPECT_EQ(_validPKCS1SignatureSHA512, signature);
}

/**
 * @brief Successful signature creation and verification for PKCS1
 * - SHA256 hashing
 * - SHA512 hashing
 */
TEST_F(SignatureTest, testSuccessfulRsaSignatureAndVerificationPKCS1)
{
    std::vector<uint8_t> signature;

    /* Sign and verify with SHA256 hashing */
    EXPECT_NO_THROW(signature = SignatureUtils::RSA::create(*_keyPairRsa, sha256PKCSPadding, _testMessageDigestSHA256));
    EXPECT_NO_THROW(SignatureUtils::RSA::verify(*_keyPairRsa, sha256PKCSPadding, signature, _testMessageDigestSHA256));

    /* Sign and verify with SHA512 hashing */
    EXPECT_NO_THROW(signature = SignatureUtils::RSA::create(*_keyPairRsa, sha512PKCSPadding, _testMessageDigestSHA512));
    EXPECT_NO_THROW(SignatureUtils::RSA::verify(*_keyPairRsa, sha512PKCSPadding, signature, _testMessageDigestSHA512));
}

/**
 * @brief Successful signature creation and verification for PSS
 * - SHA256 hashing
 * - SHA512 hashing
 *
 * Masking is SHA256 (by default)
 */
TEST_F(SignatureTest, testSuccessfulRsaSignatureAndVerificationPSSWithSHA256Masking)
{
    std::vector<uint8_t> signature;

    /* Sign and verify with SHA256 hashing */
    EXPECT_NO_THROW(signature = SignatureUtils::RSA::create(*_keyPairRsa, sha256PSSPadding, _testMessageDigestSHA256));
    EXPECT_NO_THROW(SignatureUtils::RSA::verify(*_keyPairRsa, sha256PSSPadding, signature, _testMessageDigestSHA256));

    /* Sign and verify with SHA512 hashing */
    EXPECT_NO_THROW(signature = SignatureUtils::RSA::create(*_keyPairRsa, sha512PSSPadding, _testMessageDigestSHA512));
    EXPECT_NO_THROW(SignatureUtils::RSA::verify(*_keyPairRsa, sha512PSSPadding, signature, _testMessageDigestSHA512));
}

/**
 * @brief Successful signature creation and verification for PSS with SHA512 masking
 */
TEST_F(SignatureTest, testSuccessfulRsaSignatureAndVerificationPSSWithSHA512Masking)
{
    std::vector<uint8_t> signature;

    EXPECT_NO_THROW(signature
                            = SignatureUtils::RSA::create(*_keyPairRsa,
                                                          PSSPadding(DigestTypes::SHA512, DigestTypes::SHA512),
                                                          _testMessageDigestSHA512));
    EXPECT_NO_THROW(SignatureUtils::RSA::verify(*_keyPairRsa,
                                                PSSPadding(DigestTypes::SHA512, DigestTypes::SHA512),
                                                signature,
                                                _testMessageDigestSHA512));
}

/**
 * @brief Successful signature creation and verification for PSS with non-default salt length
 */
TEST_F(SignatureTest, testSuccessfulRsaSignatureAndVerificationPSSWithNonDefaultSaltLength)
{
    std::vector<uint8_t> signature;

    EXPECT_NO_THROW(
            signature = SignatureUtils::RSA::create(
                    *_keyPairRsa, PSSPadding(DigestTypes::SHA512, DigestTypes::SHA512, 13), _testMessageDigestSHA512));
    EXPECT_NO_THROW(SignatureUtils::RSA::verify(*_keyPairRsa,
                                                PSSPadding(DigestTypes::SHA512, DigestTypes::SHA512, 13),
                                                signature,
                                                _testMessageDigestSHA512));
}

/**
 * @brief Unsuccessful case where the message digest length is incompatible with the padding mode,
 *        when using PKCS1.
 */
TEST_F(SignatureTest, testUnsuccessfulRsaSignatureWithInvalidDigestLengthPKCS1)
{
    std::vector<uint8_t> signature;
    std::vector<uint8_t> messageDigest;
    const std::string _testMessage{"Hello World!"};

    messageDigest = sha256(reinterpret_cast<const uint8_t *>(_testMessage.c_str()),
                           reinterpret_cast<size_t>(_testMessage.length()));

    EXPECT_THROW(signature = SignatureUtils::RSA::create(*_keyPairRsa, sha512PKCSPadding, messageDigest),
                 MoCOCrWException);
}

/**
 * @brief Signature fails due to an invalid salt length value.
 */
TEST_F(SignatureTest, testUnsuccessfulRsaSignatureWithInvalidSaltLength)
{
    /* Invalid case */
    ASSERT_THROW(SignatureUtils::RSA::create(*_keyPairRsa,
                                             PSSPadding(DigestTypes::SHA256, DigestTypes::SHA256, -200),
                                             _testMessageDigestSHA256),
                 MoCOCrWException);
}

/**
 * @brief Successful verification using a valid public key.
 */
TEST_F(SignatureTest, testSuccessfulRsaVerificationWithValidPublicKey)
{
    auto key = mococrw::AsymmetricKeypair::readPublicKeyFromPEM(_validRsaPublicKey);

    EXPECT_NO_THROW(
            SignatureUtils::RSA::verify(key, sha256PKCSPadding, _validPKCS1SignatureSHA256, _testMessageDigestSHA256));
}

/**
 * @brief Successful verification using a Certificate.
 */
TEST_F(SignatureTest, testSuccessfulRsaVerificationWithCertificate)
{

    /* Load certificate */
    _root1_RsaCert = std::make_unique<X509Certificate>(loadCertFromFile("signCertificate.pem"));

    /* Verify with message digest */
    EXPECT_NO_THROW(SignatureUtils::RSA::verify(
            *_root1_RsaCert, sha256PKCSPadding, _validPKCS1SignatureSHA256, _testMessageDigestSHA256));
}

/**
 * @brief Verification fails due to an invalid public key.
 */
TEST_F(SignatureTest, testUnsuccessfulRsaVerificationWithWrongPublicKey)
{
    std::vector<uint8_t> signature;
    EXPECT_NO_THROW(signature = SignatureUtils::RSA::create(*_keyPairRsa, sha256PSSPadding, _testMessageDigestSHA256));

    /* Load Public Key file */
    _root1_RsaPubkey = std::make_unique<AsymmetricPublicKey>(loadPubkeyFromFile("root1.pubkey.pem"));

    /* Using different public key */
    ASSERT_THROW(SignatureUtils::RSA::verify(*_root1_RsaPubkey, sha256PSSPadding, signature, _testMessageDigestSHA256),
                 MoCOCrWException);
}

/**
 * @brief Verification fails due to an invalid padding mode.
 */
TEST_F(SignatureTest, testUnsuccessfulRsaVerificationWithWrongPadding)
{
    std::vector<uint8_t> signature;
    EXPECT_NO_THROW(signature = SignatureUtils::RSA::create(*_keyPairRsa, sha256PSSPadding, _testMessageDigestSHA256));

    ASSERT_THROW(SignatureUtils::RSA::verify(*_keyPairRsa, sha256PKCSPadding, signature, _testMessageDigestSHA256),
                 MoCOCrWException);
}

/**
 * @brief Verification fails due to an invalid hashing function.
 */
TEST_F(SignatureTest, testUnsuccessfulRsaVerificationWithWrongHashingFunction)
{
    std::vector<uint8_t> signature;
    EXPECT_NO_THROW(signature = SignatureUtils::RSA::create(*_keyPairRsa, sha256PSSPadding, _testMessageDigestSHA256));

    ASSERT_THROW(SignatureUtils::RSA::verify(*_keyPairRsa, sha512PSSPadding, signature, _testMessageDigestSHA256),
                 MoCOCrWException);
}

/**
 * @brief Verification fails due to an invalid masking function.
 */
TEST_F(SignatureTest, testUnsuccessfulRsaVerificationWithWrongMaskingFunction)
{
    std::vector<uint8_t> signature;
    EXPECT_NO_THROW(signature = SignatureUtils::RSA::create(*_keyPairRsa, sha256PSSPadding, _testMessageDigestSHA256));

    ASSERT_THROW(SignatureUtils::RSA::verify(*_keyPairRsa,
                                             PSSPadding(DigestTypes::SHA256, DigestTypes::SHA512),
                                             signature,
                                             _testMessageDigestSHA256),
                 MoCOCrWException);
}

/**
 * @brief Verification fails due to an invalid salt length.
 */
TEST_F(SignatureTest, testUnsuccessfulRsaVerificationWithWrongSaltLength)
{
    std::vector<uint8_t> signature;
    EXPECT_NO_THROW(signature = SignatureUtils::RSA::create(*_keyPairRsa, sha256PSSPadding, _testMessageDigestSHA256));

    ASSERT_THROW(SignatureUtils::RSA::verify(*_keyPairRsa,
                                             PSSPadding(DigestTypes::SHA256, DigestTypes::SHA256, 2),
                                             signature,
                                             _testMessageDigestSHA256),
                 MoCOCrWException);
}

/**
 * @brief Verification fails due to an invalid (modified) signature.
 */
TEST_F(SignatureTest, testUnsuccessfulRsaVerificationWithModifiedSignature)
{
    std::vector<uint8_t> signature;
    EXPECT_NO_THROW(signature = SignatureUtils::RSA::create(*_keyPairRsa, sha256PSSPadding, _testMessageDigestSHA256));

    /* The signature is modified and should now be invalid. */
    std::random_shuffle(signature.begin(), signature.end());
    ASSERT_THROW(SignatureUtils::RSA::verify(*_keyPairRsa,
                                             PSSPadding(DigestTypes::SHA256, DigestTypes::SHA256),
                                             signature,
                                             _testMessageDigestSHA256),
                 MoCOCrWException);
}

/**
 * @brief Successful signature creation and verification with ECC keys
 */
TEST_F(SignatureTest, testSuccessfulEccSignatureAndVerification)
{
    std::vector<uint8_t> signature;

    /* Sign and verify with SHA1 hashing */
    EXPECT_NO_THROW(signature = SignatureUtils::ECC::create(*_keyPairEcc, DigestTypes::SHA1, _testMessageDigestSHA1));
    EXPECT_NO_THROW(SignatureUtils::ECC::verify(*_keyPairEcc, signature, DigestTypes::SHA1, _testMessageDigestSHA1));

    /* Sign and verify with SHA256 hashing */
    EXPECT_NO_THROW(signature = SignatureUtils::ECC::create(*_keyPairEcc, DigestTypes::SHA256, _testMessageDigestSHA256));
    EXPECT_NO_THROW(SignatureUtils::ECC::verify(*_keyPairEcc, signature, DigestTypes::SHA256, _testMessageDigestSHA256));

    /* Sign and verify with SHA512 hashing */
    EXPECT_NO_THROW(signature = SignatureUtils::ECC::create(*_keyPairEcc, DigestTypes::SHA512, _testMessageDigestSHA512));
    EXPECT_NO_THROW(SignatureUtils::ECC::verify(*_keyPairEcc, signature, DigestTypes::SHA512, _testMessageDigestSHA512));
}

/**
 * @brief Successful signature verification using a valid ECC public key.
 */
TEST_F(SignatureTest, testSuccessfulEccVerificationWithValidEccPublicKey)
{

    auto publicKey = mococrw::AsymmetricKeypair::readPublicKeyFromPEM(_validEccPublicKey);

    ASSERT_EQ(publicKey.getType(), AsymmetricKey::KeyTypes::ECC);
    EXPECT_NO_THROW(SignatureUtils::ECC::verify(
          publicKey, _validEccSignatureSHA1, DigestTypes::SHA1, _testMessageDigestSHA1));
}

/**
 * @brief Tests that the ECC verify method throws a MoCOCrWException exception when the signature is invalid.
 */
TEST_F(SignatureTest, testUnsuccessfulEccVerificationWithInvalidSignature)
{
    std::vector<uint8_t> signature;
    EXPECT_NO_THROW(signature = SignatureUtils::ECC::create(*_keyPairEcc, DigestTypes::SHA1, _testMessageDigestSHA1));

    /* The signature is modified and should now be invalid. */
    std::random_shuffle(signature.begin(), signature.end());
    ASSERT_THROW(SignatureUtils::ECC::verify(*_keyPairEcc, signature, DigestTypes::SHA1, _testMessageDigestSHA1),
                 MoCOCrWException);
}

/**
 * @brief Successful verification using an ECC Certificate.
 */
TEST_F(SignatureTest, testSuccessfulEccVerificationWithCertificate)
{
    /* Load certificate */
    _root1_RsaCert = std::make_unique<X509Certificate>(X509Certificate::fromPEM(_validEccCertificate));

    /* Verify with message digest */
    EXPECT_NO_THROW(SignatureUtils::ECC::verify(
            *_root1_RsaCert, _validEccSignatureSHA1, DigestTypes::SHA1, _testMessageDigestSHA1));
}

/**
 * @brief Unsucessful verification due to an invalid ECC public key.
 */
TEST_F(SignatureTest, testUnsuccessfulEccVerificationWithWrongPublicKey)
{
    auto publicKey = mococrw::AsymmetricKeypair::readPublicKeyFromPEM(_invalidEccPublicKey);

    ASSERT_EQ(publicKey.getType(), AsymmetricKey::KeyTypes::ECC);
    ASSERT_THROW(SignatureUtils::ECC::verify(publicKey,
                                             _validEccSignatureSHA1,
                                             DigestTypes::SHA1,
                                             _testMessageDigestSHA1),
                 MoCOCrWException);
}
