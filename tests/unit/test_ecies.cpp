/*
 * #%L
 * %%
 * Copyright (C) 2020 BMW Car IT GmbH
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mococrw/ecies.h"
#include "mococrw/key.h"
#include "mococrw/openssl_wrap.h"
#include "mococrw/symmetric_crypto.h"
#include "mococrw/util.h"

using namespace mococrw;
using namespace ::testing;

using testing::Eq;
namespace myTest
{
const SymmetricCipherMode mode = SymmetricCipherMode::CBC;
const SymmetricCipherKeySize keySize = SymmetricCipherKeySize::S_256;
const SymmetricCipherPadding padding = SymmetricCipherPadding::PKCS;

static const auto macFunc =
        [](const std::vector<uint8_t> &key) -> std::unique_ptr<MessageAuthenticationCode> {
    return std::make_unique<mococrw::HMAC>(openssl::DigestTypes::SHA512, key);
};

static const auto randomKey = AsymmetricKeypair(ECCSpec().generate().internal());

class ECIESTests : public ::testing::Test
{
public:
    void SetUp() override
    {
        const std::vector<uint8_t> zeroIV =
                std::vector<uint8_t>(AESCipherBuilder::getDefaultIVLength(mode));

        auto kdf = std::make_shared<X963KDF>(openssl::DigestTypes::SHA512);

        auto cipherDecFunc =
                [zeroIV](const std::vector<uint8_t> &key) -> std::unique_ptr<SymmetricCipherI> {
            return AESCipherBuilder(mode, keySize, key)
                    .setIV(zeroIV)
                    .setPadding(padding)
                    .buildDecryptor();
        };

        auto cipherEncFunc =
                [zeroIV](const std::vector<uint8_t> &key) -> std::unique_ptr<SymmetricCipherI> {
            return AESCipherBuilder(mode, keySize, key)
                    .setIV(zeroIV)
                    .setPadding(padding)
                    .buildEncryptor();
        };

        encBuilder.setKDF(kdf)
                .setMacFactoryFunction(macFunc)
                .setMacKeySize(512 / 8)
                .setSymmetricCipherFactoryFunction(cipherEncFunc)
                .setSymmetricCipherKeySize(256 / 8);

        decBuilder.setKDF(kdf)
                .setMacFactoryFunction(macFunc)
                .setMacKeySize(512 / 8)
                .setSymmetricCipherFactoryFunction(cipherDecFunc)
                .setSymmetricCipherKeySize(256 / 8);
    }

protected:
    AsymmetricKeypair secp384Key =
            AsymmetricKeypair::generate(ECCSpec(openssl::ellipticCurveNid::SECP_384r1));
    AsymmetricPublicKey secp384PublicKey = secp384Key;
    ECIESCtxBuilder encBuilder;
    ECIESCtxBuilder decBuilder;
};

TEST_F(ECIESTests, testWithoutSalt)
{
    std::vector<uint8_t> testString = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    auto encCtx = encBuilder.buildEncryptionCtx(secp384PublicKey);
    encCtx->update(testString);
    auto ciphertext = encCtx->finish();
    auto mac = encCtx->getMAC();
    auto ephKey = encCtx->getEphemeralKey();

    auto decCtx = decBuilder.buildDecryptionCtx(secp384Key, ephKey);
    decCtx->update(ciphertext);
    decCtx->setMAC(mac);
    auto result = decCtx->finish();
    EXPECT_EQ(testString, result);
}

TEST_F(ECIESTests, testWithSalts)
{
    std::vector<uint8_t> kdfSalt = {'T', 'e', 's', 't', 'K', 'D', 'F'};
    std::vector<uint8_t> macSalt = {'T', 'e', 's', 't', 'M', 'A', 'C'};
    std::vector<uint8_t> testString = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    encBuilder.setKDFSalt(kdfSalt);
    encBuilder.setMACSalt(macSalt);

    auto encCtx = encBuilder.buildEncryptionCtx(secp384PublicKey);

    encCtx->update(testString);
    auto ciphertext = encCtx->finish();
    auto mac = encCtx->getMAC();
    auto ephKey = encCtx->getEphemeralKey();

    decBuilder.setKDFSalt(kdfSalt);
    decBuilder.setMACSalt(macSalt);

    auto decCtx = decBuilder.buildDecryptionCtx(secp384Key, ephKey);
    decCtx->update(ciphertext);
    decCtx->setMAC(mac);
    auto result = decCtx->finish();
    EXPECT_EQ(testString, result);
}

struct testData
{
    std::string privateKey;
    std::string ephemeralKey;
    std::string ciphertext;
    std::string macTag;
    std::string plaintext;
};

static std::vector<testData> prepareTestDataForECIESTests()
{
    std::vector<testData> data{
            {"-----BEGIN EC PRIVATE KEY-----\n"
             "MIGkAgEBBDBUGq/lzm93hmnIVdr5UWMnSnnN1Kd0EVkHxRJ0BFzQcUJxrH579/04\n"
             "jQbIfYP4VPCgBwYFK4EEACKhZANiAARl2UGjmJow8rUCXZkGXTlRnhQXImCC7ISO\n"
             "nqzT64Nzpfzsnv3FsNjjk5MCh4WfZRaZwApNyWLX5HwZhF8ZOgC41Xryd8pBREKu\n"
             "Qqd2w1/Fb1aRsmmI893lRDwb0qRb5Ug=\n"
             "-----END EC PRIVATE KEY-----\n",
             "0437D97E1299CF430163A11FC87B7B8FB647BD98EE8B5BAE31C3BB1EE897A77BAFA20F94F6CE0B9174899"
             "6359000B"
             "47E56F2587825E4F01CEFF9BBDDE8ED17DDEE8BD46BD409DFF7FF48E9F7A869FE3F9D8174F788CD21C2D8"
             "EAE5BF25"
             "6884AA89",
             "90C4509BC7C9FFE404F6B063E2781655323BF402645C241A5F57E556AB397E6C4EFED563A77A66998A464"
             "5C7A24B82"
             "34",
             "46805E4419BEB16F7EC8D234699A1E266398819B46AD095AF7A49CC683E7561ABFB24E3DF5798B3E14511"
             "10A8F663F15"
             "47B640CE65112051F4F8481DCE578F4D",
             "4AB1D2A13A956C83D58B0AD023115256F8720C7E6E332B47906D5D0BA5257DE7"},
            {
                    R"(-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDgg+ZjkIkHJdh4q11J6Cq79p+RNHJS9cd7SdpBCVutIOaR2LKCbyL1
/9evzF5ACnqgBwYFK4EEACKhZANiAAQLIoblj22/vmy4gDBvUdUoI646hedLc+DV
aiG8qUiSlNb7mAvorXIsUImPYV8F0WRLUoVY+TJ7K2yzWl5G9jwP54v8tuXaGYJ6
K/rWsgsSxMP3CigGs1zZm4PkPxhpkgE=
-----END EC PRIVATE KEY-----
            )",
                    "04EF3F43C81D752D0DA9EB550357F77864C987E0D83D834175FDD6AB6B0189D0D9D2DCB914328F"
                    "E1A961F758FBEE92"
                    "530EF4E2FCE19D422A85D98B61D34C87A122554F515B4587AB15F76CBC27080F6C2FEE444D6955"
                    "C53D39193C23CBAA"
                    "72F15B",
                    "260F659ECB79C9623DEEE0A492E8A1292521C52DE98085D7BBBEBD3E73240E388AFC89F61E58B8"
                    "3CE60D50C9"
                    "7E17B2B5",
                    "DADB28BE9D7F78A02BA777E76312284B7D92D9CE9AC97967581463F76674C6837C96D74DA54728"
                    "17B1740278D91164"
                    "7666CA3F2274DD0EB0E82A28468E32F002",
                    "90CFF07A8D14865F4A1F90381E4960B5E2DB8F8764B1F166953220CB7FE1C2F1"},
            {
                    R"(-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDD9VUIJePHKopQFTy7zDfT2X3ADbiZ2MBIZ0ArXn4UUVRQgv2I/6MRj
YAkHUvmG4O+gBwYFK4EEACKhZANiAATZQFcxwF+0KMiNTPK5Fl7ULOX/+F8VW5Rb
5f7Ub2ozjysP/0ShHox8vkrJm92FahIxx2yb1O1EYK6jMqlqUP6jhpoHMB1wQN+D
h+caydSmaUbi7PaJlGgJ4TVrcsoPTZ8=
-----END EC PRIVATE KEY-----
            )",
                    "0400FD13363AF3768E2AC8324FBDF23E65FA316966A67B797F6E42C3AF8DA2AFC721B809A2A91A"
                    "7CD996256EDAC52A"
                    "2257FAEBF13A5C09111CE8EC09C35E724EFACEA818884B962F01F4538CE31B340B3D65F75ED85B"
                    "F0F8B5AF07A717F4"
                    "7EC9C6",
                    "552786BE64E07D0D1ABAF640A969087C15C902F5D23F173F9626C4D1B31B20C4999B8F75910228"
                    "EE496E4388"
                    "20B09BB0",
                    "16FD040C6D66CC560B1DFE4A19997CDA850A9F0C42BAA3BED04FD00EB0932DAAA01D5F36EC9125"
                    "8561E8AE"
                    "369E693B73DB8E6C86DD3CBE81F7A910980A6A261D",
                    "1B8B4EC1710E6B10F0BA941F4068901C1BC8208A250AB933EFFF6B43BC56BCAB"},
            {
                    R"(-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDkMr1CpLbqwrEX0/o4KicQCNJjKymWwgheAaV/twUQzLXFoqF8RB5z
e8qNQfuQLAqgBwYFK4EEACKhZANiAAS5q5jGApdpsCNMjpX8IJAZSjH1pSsDjqlF
QO8Os+ownRjfVcaQcl1geYUy2FquG6kywg8CK/CCp7trwOC3T1aFUcPnW+/XRNtb
LGRim6SJgonqUn/eSLKdJNk2W7Odthk=
-----END EC PRIVATE KEY-----
            )",
                    "04B00689869B4418C18B5EC8699A33984ED10CA7BBACA037A462715E841846338B4EAFF6EB93CD"
                    "C9875EB1D6642E5B"
                    "EB25FE994117E583DC2512C70CB83FD2B9A278FD8BA8503D27A2A96A2B17E93FE6FCA3592AD741"
                    "78377E609F215428"
                    "D18384",
                    "4D108CEC5BF3E9FE32F5A7F98F49D0C176655DD92CE6A27197F8FA884F6A6F703ECAE253916291"
                    "E01082540A"
                    "CF22449E",
                    "0A452DBDDD91624E4552B7DA40049251BAD5FA48C1D6D6B4F4499A918B7CFAC391A51006AA8625"
                    "60BBD2CC"
                    "956D3BBC9A50CD758851142C78675E1334EEF796F6",
                    "5E83A26BE96A19856A6E25A102A8794EC1BFED25EA1B1EB4EA188076996BCFAB"},
            {
                    R"(-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDVqHt0b/aKqVewnnW9mp80zzPWc93KTveEXsEnyN0Rgj3nheFSdDHL
z72mLpazSeagBwYFK4EEACKhZANiAASzMIjYvaK0iCR9Snmx2BFFAjaZrCZAMhMh
0wjM909bwjZt6qd4JJtDc7PDctQQs490bVP8LHUaPbWh4VZHIeX3jz0hKOobpzad
axVqEbJ5jAX6XNP5AlBLzYHp24XAZwY=
-----END EC PRIVATE KEY-----
            )",
                    "0478E3A07F7111C8341A9BBC7FB979F9B1CB27CB0B20E5A0B587C9F43CE1464F53C17461E82F12"
                    "9684D8E6B7B06D74"
                    "AD4AA590985174917E063CEE975E85DA0100626F701EC0278437466B28578852B0EB1684606BEF"
                    "FF22B9FF6D591C44"
                    "53111A",
                    "1184FC9E16AF814F87DB3CA26F84B408DD876471215F59543D811E6C3E51BA9B0CA446440BBA8A"
                    "935E99B029"
                    "5708F699",
                    "D29CAB796BC5900C4570B8697F41FED528BA84A339080192E31344FB6F2FF61AF05770BEBA1EA0"
                    "A0C7A119"
                    "D3C4862D7CE62C4D4176F2178FAAD011A7935A5EAD",
                    "74E0490C9C7E0EE9B4AF03AB44ABDD1479BEC054DDA34A106263535B82B05472"}};
    return data;
}

void testECIES(struct testData data)
{
    /* Read and set the private key */
    AsymmetricKeypair privKey(AsymmetricKeypair::readPrivateKeyFromPEM(data.privateKey, ""));
    ECIESCtxBuilder decBuilder;

    /* Generate the ephemeral Key */
    std::shared_ptr<AsymmetricKey::Spec> keySpec = privKey.getKeySpec();
    auto eccSpec = std::dynamic_pointer_cast<ECCSpec>(keySpec);
    ASSERT_TRUE(eccSpec != nullptr);
    AsymmetricPublicKey ephKey =
            AsymmetricPublicKey::fromECPoint(eccSpec, utility::fromHex(data.ephemeralKey));

    /* Use the default values, which should match here. */
    auto decCtx = decBuilder.buildDecryptionCtx(privKey, ephKey);

    /* Decrypt the ciphertext */
    decCtx->update(utility::fromHex(data.ciphertext));

    /* Set the received mac value */
    decCtx->setMAC(utility::fromHex(data.macTag));

    /* Get the plaintext and verify the MAC */
    auto result = decCtx->finish();

    ASSERT_EQ(result, utility::fromHex(data.plaintext));
}

class ECIESTest : public testing::TestWithParam<testData>
{
};
INSTANTIATE_TEST_SUITE_P(ecies, ECIESTest, testing::ValuesIn(prepareTestDataForECIESTests()));

TEST_P(ECIESTest, testWithTestVectors) { testECIES(GetParam()); }

TEST(ECIESBuilderTest, checkForAllNecessaryDefaultValues)
{
    /* Testing for missing parameters. This is the same for Encryption and decryption */
    ECIESCtxBuilder decBuilder;
    decBuilder.buildDecryptionCtx(randomKey, randomKey);
}

TEST(ECIESBuilderTest, incompleteBuilder1)
{
    ECIESCtxBuilder decBuilder;
    std::function<std::unique_ptr<MessageAuthenticationCode>(const std::vector<uint8_t> &)>
            macFunc = [](const std::vector<uint8_t> &key) {
                (void)key;
                return nullptr;
            };
    decBuilder.setMacFactoryFunction(macFunc);
    EXPECT_THROW(decBuilder.buildDecryptionCtx(randomKey, randomKey), MoCOCrWException);
}

TEST(ECIESBuilderTest, incompleteBuilder2)
{
    ECIESCtxBuilder decBuilder;
    decBuilder.setMacKeySize(1);
    EXPECT_THROW(decBuilder.buildDecryptionCtx(randomKey, randomKey), MoCOCrWException);
}

TEST(ECIESBuilderTest, incompleteBuilder3)
{
    ECIESCtxBuilder decBuilder;
    std::function<std::unique_ptr<SymmetricCipherI>(const std::vector<uint8_t> &)> symCipherFunc =
            [](const std::vector<uint8_t> &key) {
                (void)key;
                return nullptr;
            };
    decBuilder.setSymmetricCipherFactoryFunction(symCipherFunc);
    EXPECT_THROW(decBuilder.buildDecryptionCtx(randomKey, randomKey), MoCOCrWException);
}

TEST(ECIESBuilderTest, incompleteBuilder4)
{
    ECIESCtxBuilder decBuilder;
    decBuilder.setSymmetricCipherKeySize(1);
    EXPECT_THROW(decBuilder.buildDecryptionCtx(randomKey, randomKey), MoCOCrWException);
}

TEST(ECIESTest, certTest)
{
    std::string privKeyString{R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOGOxWwDXOKW482FT+jFUaS5CQS8iadU78f60nBN3zTUoAoGCCqGSM49
AwEHoUQDQgAEYBZUUP11bhdM/eNWzSLD1MDTBmEgWkJDnIR4UfKvo2mgShST4U1S
TcJF1xBUhF5ecYo7g/Niwpw8SwG1QH0a+A==
-----END EC PRIVATE KEY-----)"};

    std::string certString{R"(-----BEGIN CERTIFICATE-----
MIICcTCCAhegAwIBAgIURdMbES7SekKg3835htjY+nay3kYwCgYIKoZIzj0EAwIw
gY0xCzAJBgNVBAYTAkRFMQswCQYDVQQIDAJCVzEMMAoGA1UEBwwDVWxtMRIwEAYD
VQQKDAlCTVcgQ2FySVQxDTALBgNVBAsMBEpDLTcxETAPBgNVBAMMCERldi1UZWFt
MS0wKwYJKoZIhvcNAQkBFh5NR1UtU2VjdXJpdHktVGVhbUBsaXN0LmJtdy5jb20w
HhcNMjAwNDE0MTY1NjMxWhcNMjEwNDE0MTY1NjMxWjCBjTELMAkGA1UEBhMCREUx
CzAJBgNVBAgMAkJXMQwwCgYDVQQHDANVbG0xEjAQBgNVBAoMCUJNVyBDYXJJVDEN
MAsGA1UECwwESkMtNzERMA8GA1UEAwwIRGV2LVRlYW0xLTArBgkqhkiG9w0BCQEW
Hk1HVS1TZWN1cml0eS1UZWFtQGxpc3QuYm13LmNvbTBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABGAWVFD9dW4XTP3jVs0iw9TA0wZhIFpCQ5yEeFHyr6NpoEoUk+FN
Uk3CRdcQVIReXnGKO4PzYsKcPEsBtUB9GvijUzBRMB0GA1UdDgQWBBSi+rthnvaF
Hd/ceL/FukSRixvuAzAfBgNVHSMEGDAWgBSi+rthnvaFHd/ceL/FukSRixvuAzAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIF/JBFRAROnQAqmpcs5f
+Q8+M51Rj0qS5X8+7d/eWfEXAiEAzih37HPbeFvoP36Xqh4GpXfsU1BZp9RB4Q7S
VndFGPg=
-----END CERTIFICATE-----)"};

    auto privKey(AsymmetricKeypair::readPrivateKeyFromPEM(privKeyString, ""));
    auto cert = X509Certificate::fromPEM(certString);

    ECIESCtxBuilder encBuilder;
    ECIESCtxBuilder decBuilder;

    auto encCtx = encBuilder.buildEncryptionCtx(cert);

    std::vector<uint8_t> testString = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};

    encCtx->update(testString);
    auto ciphertext = encCtx->finish();
    auto mac = encCtx->getMAC();
    auto ephKey = encCtx->getEphemeralKey();

    auto decCtx = decBuilder.buildDecryptionCtx(privKey, ephKey);
    decCtx->update(ciphertext);
    decCtx->setMAC(mac);
    auto result = decCtx->finish();
    EXPECT_EQ(testString, result);
}

TEST(ECIESBuilderTest, exceptionThrowTest)
{
    /* Testing for missing parameters. This is the same for Encryption and decryption */
    ECIESCtxBuilder decBuilder;
    decBuilder.setMacKeySize(1);
    decBuilder.setMacFactoryFunction(
            [](const std::vector<uint8_t> &key) -> std::unique_ptr<MessageAuthenticationCode> {
                throw MoCOCrWException("testException");
                return std::make_unique<mococrw::HMAC>(openssl::DigestTypes::SHA512, key);
            });
    EXPECT_THROW(auto encCtx = decBuilder.buildEncryptionCtx(randomKey), MoCOCrWException);
}
}  // namespace myTest
