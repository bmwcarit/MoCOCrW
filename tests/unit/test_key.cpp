/*
 * #%L
 * %%
 * Copyright (C) 2022 BMW Car IT GmbH
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

#include "key.cpp"
#include "util.cpp"

#ifdef MOCOCRW_HSM_ENABLED
#include "hsm_mock.h"
#endif

using namespace mococrw;
using namespace ::testing;

class KeyHandlingTests : public ::testing::Test
{
public:
    void SetUp() override;

    static std::string _pemEccPrivKeySect409k1;
    static std::string _pemEccPubKeySect409k1;
    static std::string _pemEccPrivKeyEd25519;
    static std::string _pemEccPubKeyEd25519;

protected:
    mococrw::AsymmetricKeypair _rsaKeyPair = AsymmetricKeypair::generateRSA();
    mococrw::AsymmetricKeypair _rsaKeyPair2 = AsymmetricKeypair::generateRSA();
    mococrw::AsymmetricKeypair _eccKeyPairDefault = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _eccKeyPairDefault2 = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _eccKeyPairSect571r1 = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _eccKeyPairSecp521r1 = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _Ed448KeyPair = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _Ed448KeyPair_2 = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _Ed25519KeyPair = AsymmetricKeypair::generateECC();
    mococrw::AsymmetricKeypair _Ed25519KeyPair_2 = AsymmetricKeypair::generateECC();
};

void KeyHandlingTests::SetUp()
{
    _rsaKeyPair = AsymmetricKeypair::generateRSA();
    _rsaKeyPair2 = AsymmetricKeypair::generateRSA();

    _eccKeyPairDefault = AsymmetricKeypair::generateECC();
    _eccKeyPairDefault2 = AsymmetricKeypair::generateECC();

    _eccKeyPairSect571r1 =
            AsymmetricKeypair::generate(mococrw::ECCSpec{openssl::ellipticCurveNid::SECT_571r1});
    _eccKeyPairSecp521r1 =
            AsymmetricKeypair::generate(mococrw::ECCSpec{openssl::ellipticCurveNid::SECP_521r1});

    _Ed448KeyPair = AsymmetricKeypair::generate(mococrw::ECCSpec{openssl::ellipticCurveNid::Ed448});
    _Ed448KeyPair_2 =
            AsymmetricKeypair::generate(mococrw::ECCSpec{openssl::ellipticCurveNid::Ed448});

    _Ed25519KeyPair =
            AsymmetricKeypair::generate(mococrw::ECCSpec{openssl::ellipticCurveNid::Ed25519});
    _Ed25519KeyPair_2 =
            AsymmetricKeypair::generate(mococrw::ECCSpec{openssl::ellipticCurveNid::Ed25519});
}

std::string KeyHandlingTests::_pemEccPrivKeySect409k1{R"(-----BEGIN PRIVATE KEY-----
MIHCAgEAMBAGByqGSM49AgEGBSuBBAAkBIGqMIGnAgEBBDQAF2zFhKyxJiI7bGvG
Mw9rq7DUvrqTDJMHeRttpsZc0i9tFbvmaT2J5U39/RkseDha2b87oWwDagAEAAdj
oVwkpy9CPA8RU3sd0aXV/XnHw5nE7HgINd6ApxCaknRebk4Vgbgz04588YqjqQpQ
TAA+hxkUt1ZInurAHTt/ECQpvt1YOTBgNigakbLzq1LsbbyLWJsH5diall6Is+lg
y2Mu1EA=
-----END PRIVATE KEY-----)"};

std::string KeyHandlingTests::_pemEccPubKeySect409k1{R"(-----BEGIN PUBLIC KEY-----
MH4wEAYHKoZIzj0CAQYFK4EEACQDagAEAAdjoVwkpy9CPA8RU3sd0aXV/XnHw5nE
7HgINd6ApxCaknRebk4Vgbgz04588YqjqQpQTAA+hxkUt1ZInurAHTt/ECQpvt1Y
OTBgNigakbLzq1LsbbyLWJsH5diall6Is+lgy2Mu1EA=
-----END PUBLIC KEY-----)"};

std::string KeyHandlingTests::_pemEccPrivKeyEd25519{R"(-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHP1o8LJ4jNkuTyDT6uNtqLankRkQeAyAIflqvnjutC2
-----END PRIVATE KEY-----)"};

std::string KeyHandlingTests::_pemEccPubKeyEd25519{R"(-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAlY+GiXLleFpEvVAOS/GJJTTpCA+fjRrCzjBpeLI73TY=
-----END PUBLIC KEY-----)"};

TEST_F(KeyHandlingTests, testGeneratedKeyIsNotNull)
{
    ASSERT_THAT(_rsaKeyPair.internal(), NotNull());
    ASSERT_THAT(_rsaKeyPair2.internal(), NotNull());

    ASSERT_THAT(_eccKeyPairDefault.internal(), NotNull());
    ASSERT_THAT(_eccKeyPairDefault2.internal(), NotNull());

    ASSERT_THAT(_eccKeyPairSecp521r1.internal(), NotNull());
    ASSERT_THAT(_eccKeyPairSect571r1.internal(), NotNull());

    ASSERT_THAT(_Ed448KeyPair.internal(), NotNull());
    ASSERT_THAT(_Ed25519KeyPair.internal(), NotNull());
}

TEST_F(KeyHandlingTests, testPublicKeyPemIsReproducible)
{
    const auto pemOfKey = _rsaKeyPair.publicKeyToPem();
    const auto pemOfKey2 = _rsaKeyPair.publicKeyToPem();

    const auto pemOfEccKey = _eccKeyPairDefault.publicKeyToPem();
    const auto pemOfEccKey2 = _eccKeyPairDefault.publicKeyToPem();

    const auto pemOfSectEccKey = _eccKeyPairSect571r1.publicKeyToPem();
    const auto pemOfSectEccKey2 = _eccKeyPairSect571r1.publicKeyToPem();

    const auto pemOfEd448Key = _Ed448KeyPair.publicKeyToPem();
    const auto pemOfEd448Key2 = _Ed448KeyPair.publicKeyToPem();

    const auto pemOfEd25519Key = _Ed25519KeyPair.publicKeyToPem();
    const auto pemOfEd25519Key2 = _Ed25519KeyPair.publicKeyToPem();

    ASSERT_EQ(pemOfKey, pemOfKey2);
    ASSERT_EQ(pemOfEccKey, pemOfEccKey2);
    ASSERT_EQ(pemOfSectEccKey, pemOfSectEccKey2);
    ASSERT_EQ(pemOfEd448Key, pemOfEd448Key2);
    ASSERT_EQ(pemOfEd25519Key, pemOfEd25519Key2);
}

TEST_F(KeyHandlingTests, testPubKeyFromSavedPemIsSameAsOriginalInOpenSSLObject)
{
    const auto pemOfPubkey = _rsaKeyPair.publicKeyToPem();
    const auto pemOfEccPubkey = _eccKeyPairDefault.publicKeyToPem();
    const auto pemOfSecpEccPubkey = _eccKeyPairSecp521r1.publicKeyToPem();
    const auto pemOfEd448Key = _Ed448KeyPair.publicKeyToPem();
    const auto pemOfEd25519Key = _Ed25519KeyPair.publicKeyToPem();

    auto rsaParsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfPubkey);
    auto eccParsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfEccPubkey);
    auto eccSecpParsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfSecpEccPubkey);
    auto Ed448ParsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfEd448Key);
    auto Ed25519ParsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfEd25519Key);

    ASSERT_EQ(_rsaKeyPair, rsaParsedKey);
    ASSERT_EQ(_eccKeyPairDefault, eccParsedKey);
    ASSERT_EQ(_eccKeyPairSecp521r1, eccSecpParsedKey);
    ASSERT_EQ(_Ed448KeyPair, Ed448ParsedKey);
    ASSERT_EQ(_Ed25519KeyPair, Ed25519ParsedKey);
    ASSERT_NE(_eccKeyPairSecp521r1, _rsaKeyPair);
}

TEST_F(KeyHandlingTests, testReadExternalEccPEMKey)
{
    /*Read private and public key from pem string*/
    auto eccPrivKey = mococrw::AsymmetricKeypair::readPrivateKeyFromPEM(
            KeyHandlingTests::_pemEccPrivKeySect409k1, "");
    auto eccPubKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(
            KeyHandlingTests::_pemEccPubKeySect409k1);

    /*Check key type and curve*/
    EXPECT_EQ(eccPrivKey.getType(), AsymmetricKey::KeyTypes::ECC);
    EXPECT_EQ(eccPubKey.getType(), AsymmetricKey::KeyTypes::ECC);

    auto privSpec = eccPrivKey.getKeySpec();
    auto pubSpec = eccPubKey.getKeySpec();
    EXPECT_EQ(dynamic_cast<ECCSpec *>(privSpec.get())->curve(),
              openssl::ellipticCurveNid::SECT_409k1);
    EXPECT_EQ(dynamic_cast<ECCSpec *>(pubSpec.get())->curve(),
              openssl::ellipticCurveNid::SECT_409k1);

    /*Write key to a new pem file and read back to compare with original*/
    /*Public key*/
    const auto pemOfPubkey = eccPubKey.publicKeyToPem();
    auto parsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfPubkey);
    ASSERT_EQ(eccPubKey, parsedKey);
    /*Private key*/
    const auto pemOfPrivateKey = eccPrivKey.privateKeyToPem("secret");
    auto retrievedKeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfPrivateKey, "secret");
    ASSERT_EQ(eccPrivKey, retrievedKeyPair);
}

TEST_F(KeyHandlingTests, testReadExternalEd25519PEMKey)
{
    /*Read private and public key from pem string*/
    auto eccPrivKey = mococrw::AsymmetricKeypair::readPrivateKeyFromPEM(
            KeyHandlingTests::_pemEccPrivKeyEd25519, "");
    auto eccPubKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(
            KeyHandlingTests::_pemEccPubKeyEd25519);

    /*Check key type and curve*/
    EXPECT_EQ(eccPrivKey.getType(), AsymmetricKey::KeyTypes::ECC_ED);
    EXPECT_EQ(eccPubKey.getType(), AsymmetricKey::KeyTypes::ECC_ED);

    auto privSpec = eccPrivKey.getKeySpec();
    auto pubSpec = eccPubKey.getKeySpec();
    EXPECT_EQ(dynamic_cast<ECCSpec *>(privSpec.get())->curve(), openssl::ellipticCurveNid::Ed25519);
    EXPECT_EQ(dynamic_cast<ECCSpec *>(pubSpec.get())->curve(), openssl::ellipticCurveNid::Ed25519);

    /*Write key to a new pem file and read back to compare with original*/
    /*Public key*/
    const auto pemOfPubkey = eccPubKey.publicKeyToPem();
    auto parsedKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfPubkey);
    ASSERT_EQ(eccPubKey, parsedKey);
    /*Private key*/
    const auto pemOfPrivateKey = eccPrivKey.privateKeyToPem("secret");
    auto retrievedKeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfPrivateKey, "secret");
    ASSERT_EQ(eccPrivKey, retrievedKeyPair);
}

TEST_F(KeyHandlingTests, testPubkeyFromSavedPemIsSameAsOriginalInPEM)
{
    const auto pemOfKey = _rsaKeyPair.publicKeyToPem();
    const auto pemOfEccKey = _eccKeyPairDefault.publicKeyToPem();
    const auto pemOfSectEccKey = _eccKeyPairSect571r1.publicKeyToPem();
    const auto pemOfEd448Key = _Ed448KeyPair.publicKeyToPem();
    const auto pemOfEd25519Key = _Ed25519KeyPair.publicKeyToPem();

    auto parsedRsaKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfKey);
    auto parsedEccKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfEccKey);
    auto parsedSectEccKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfSectEccKey);
    auto parsedEd448Key = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfEd448Key);
    auto parsedEd25519Key = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(pemOfEd25519Key);

    ASSERT_EQ(pemOfKey, parsedRsaKey.publicKeyToPem());
    ASSERT_EQ(pemOfEccKey, parsedEccKey.publicKeyToPem());
    ASSERT_EQ(pemOfSectEccKey, parsedSectEccKey.publicKeyToPem());
    ASSERT_EQ(pemOfEd448Key, parsedEd448Key.publicKeyToPem());
    ASSERT_EQ(pemOfEd25519Key, parsedEd25519Key.publicKeyToPem());
}

TEST_F(KeyHandlingTests, testPrivKeyFromSavedPemIsSameAsOriginal)
{
    const auto pemOfPubKey = _rsaKeyPair.publicKeyToPem();
    const auto pemOfPrivateKey = _rsaKeyPair.privateKeyToPem("secret");

    auto retrievedKeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(pemOfPrivateKey, "secret");
    ASSERT_EQ(pemOfPubKey, retrievedKeyPair.publicKeyToPem());

    const auto pemOfEccPubKey = _eccKeyPairDefault.publicKeyToPem();
    const auto pemOfEccPrivateKey = _eccKeyPairDefault.privateKeyToPem("password");

    auto retrievedEccKeyPair =
            AsymmetricKeypair::readPrivateKeyFromPEM(pemOfEccPrivateKey, "password");
    ASSERT_EQ(pemOfEccPubKey, retrievedEccKeyPair.publicKeyToPem());

    const auto pemOfSectEccPubKey = _eccKeyPairSect571r1.publicKeyToPem();
    const auto pemOfSectEccPrivateKey = _eccKeyPairSect571r1.privateKeyToPem("santa");

    auto retrievedSectEccKeyPair =
            AsymmetricKeypair::readPrivateKeyFromPEM(pemOfSectEccPrivateKey, "santa");
    ASSERT_EQ(pemOfSectEccPubKey, retrievedSectEccKeyPair.publicKeyToPem());

    const auto pemOfSectEd448PubKey = _Ed448KeyPair.publicKeyToPem();
    const auto pemOfSectEd448PrivateKey = _Ed448KeyPair.privateKeyToPem("f00");

    auto retrievedEd448KeyPair =
            AsymmetricKeypair::readPrivateKeyFromPEM(pemOfSectEd448PrivateKey, "f00");
    ASSERT_EQ(pemOfSectEd448PubKey, retrievedEd448KeyPair.publicKeyToPem());

    const auto pemOfSectEd25519PubKey = _Ed25519KeyPair.publicKeyToPem();
    const auto pemOfSectEd25519PrivateKey = _Ed25519KeyPair.privateKeyToPem("bar");

    auto retrievedEd25519KeyPair =
            AsymmetricKeypair::readPrivateKeyFromPEM(pemOfSectEd25519PrivateKey, "bar");
    ASSERT_EQ(pemOfSectEd25519PubKey, retrievedEd25519KeyPair.publicKeyToPem());
}

#ifdef MOCOCRW_HSM_ENABLED
TEST_F(KeyHandlingTests, testKeyLoadPubKeyFromHSM)
{
    std::vector<uint8_t> keyID{0x44, 0x22, 0x11};
    std::string keyLabel{"key-label"};

    // We need to get an SSL_EVP_PKEY_Ptr so that our Mock can return it when load function
    // is called. We do this directly using the (wrapped) Bio Api.
    BioObject bio{BioObject::Types::MEM};
    bio.write(_pemEccPubKeyEd25519);
    auto resKey = _PEM_read_bio_PUBKEY(bio.internal());

    auto eccPubKey = mococrw::AsymmetricPublicKey::readPublicKeyFromPEM(
            KeyHandlingTests::_pemEccPubKeyEd25519);

    HSMMock hsmMock;
    EXPECT_CALL(hsmMock, loadPublicKey(keyLabel, keyID))
            .WillOnce(Return(ByMove(std::move(resKey))));
    EXPECT_EQ(eccPubKey, AsymmetricPublicKey::readPublicKeyFromHSM(hsmMock, keyLabel, keyID));
}

TEST_F(KeyHandlingTests, testKeyLoadPrivKeyFromHSM)
{
    std::string keyLabel = "key-label";
    std::vector<uint8_t> keyID = {0x11, 0x23, 0x33};
    std::string password = "password";

    // We need to get an SSL_EVP_PKEY_Ptr so that our Mock can return it when load function
    // is called. We do this directly using the (wrapped) Bio Api.
    BioObject bio{BioObject::Types::MEM};
    bio.write(_pemEccPrivKeyEd25519);
    auto resKey = _PEM_read_bio_PrivateKey(bio.internal(), password.c_str());

    auto eccKeyPair = AsymmetricKeypair::readPrivateKeyFromPEM(_pemEccPrivKeyEd25519, password);

    HSMMock hsmMock;
    EXPECT_CALL(hsmMock, loadPrivateKey(keyLabel, keyID))
            .WillOnce(Return(ByMove(std::move(resKey))));
    EXPECT_EQ(eccKeyPair, AsymmetricPrivateKey::readPrivateKeyFromHSM(hsmMock, keyLabel, keyID));
}

TEST_F(KeyHandlingTests, testHSMKeyGenerationECC)
{
    ECCSpec eccSpec;
    HSMMock hsmMock;
    std::string keyLabel = "key-label";
    std::vector<uint8_t> keyID{0x33, 0x33};
    EXPECT_CALL(hsmMock, generateKey(An<const ECCSpec &>(), keyLabel, keyID));
    EXPECT_NO_THROW(AsymmetricKeypair::generateKeyOnHSM(hsmMock, eccSpec, keyLabel, keyID));
}

TEST_F(KeyHandlingTests, testHSMKeyGenerationRSA)
{
    RSASpec rsaSpec;
    HSMMock hsmMock;
    std::string keyLabel = "key-label";
    std::vector<uint8_t> keyID{0x33, 0x33};
    EXPECT_CALL(hsmMock, generateKey(An<const RSASpec &>(), keyLabel, keyID));
    EXPECT_NO_THROW(AsymmetricKeypair::generateKeyOnHSM(hsmMock, rsaSpec, keyLabel, keyID));
}

TEST_F(KeyHandlingTests, testHSMKeyGenerationKeyIdTooLong)
{
    ECCSpec eccSpec;
    HSMMock hsmMock;
    std::string keyLabel = "key-label";
    // 128 characters keyId
    EXPECT_THROW(
            AsymmetricKeypair::generateKeyOnHSM(
                    hsmMock, eccSpec, keyLabel, {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13,
                                                 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
                                                 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
                                                 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
                                                 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64}),
            MoCOCrWException);
}
#endif

TEST_F(KeyHandlingTests, testBothGeneratedKeysNotTheSame)
{
    ASSERT_NE(_rsaKeyPair, _rsaKeyPair2);

    ASSERT_NE(_eccKeyPairDefault, _eccKeyPairDefault2);

    ASSERT_NE(_Ed448KeyPair, _Ed448KeyPair_2);

    ASSERT_NE(_Ed25519KeyPair, _Ed25519KeyPair_2);
}

TEST_F(KeyHandlingTests, testThrowsWhenReadingPrivateKeyUsingWrongKey)
{
    const auto pemOfPrivateKey = _rsaKeyPair.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfPrivateKey, "wrongkey"),
                 mococrw::OpenSSLException);

    const auto pemOfEccPrivateKey = _eccKeyPairDefault.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfEccPrivateKey, "wrongkey"),
                 mococrw::OpenSSLException);

    const auto pemOfSecpEccPrivateKey = _eccKeyPairSecp521r1.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfSecpEccPrivateKey, "santa"),
                 mococrw::OpenSSLException);

    const auto pemOfEd448PrivateKey = _Ed448KeyPair.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfEd448PrivateKey, "santa"),
                 mococrw::OpenSSLException);

    const auto pemOfEd25519PrivateKey = _Ed25519KeyPair.privateKeyToPem("secret");
    ASSERT_THROW(AsymmetricKeypair::readPrivateKeyFromPEM(pemOfEd25519PrivateKey, "santa"),
                 mococrw::OpenSSLException);
}

TEST_F(KeyHandlingTests, testKeyTypeChecking)
{
    EXPECT_EQ(_eccKeyPairDefault.getType(), AsymmetricKey::KeyTypes::ECC);
    EXPECT_EQ(_rsaKeyPair.getType(), AsymmetricKey::KeyTypes::RSA);
    EXPECT_EQ(_eccKeyPairSecp521r1.getType(), AsymmetricKey::KeyTypes::ECC);
    EXPECT_EQ(_eccKeyPairSect571r1.getType(), AsymmetricKey::KeyTypes::ECC);
    EXPECT_EQ(_Ed448KeyPair.getType(), AsymmetricKey::KeyTypes::ECC_ED);
    EXPECT_EQ(_Ed25519KeyPair.getType(), AsymmetricKey::KeyTypes::ECC_ED);
}

TEST_F(KeyHandlingTests, testGetKeySpec)
{
    auto defaultSpec = _eccKeyPairDefault.getKeySpec();
    auto Sect571r1Spec = _eccKeyPairSect571r1.getKeySpec();
    auto Secp521Spec = _eccKeyPairSecp521r1.getKeySpec();
    auto Ed448Spec = _Ed448KeyPair.getKeySpec();
    auto Ed25519Spec = _Ed25519KeyPair.getKeySpec();

    EXPECT_EQ(dynamic_cast<ECCSpec *>(defaultSpec.get())->curve(),
              openssl::ellipticCurveNid::PRIME_256v1);
    EXPECT_EQ(dynamic_cast<ECCSpec *>(Sect571r1Spec.get())->curve(),
              openssl::ellipticCurveNid::SECT_571r1);
    EXPECT_EQ(dynamic_cast<ECCSpec *>(Secp521Spec.get())->curve(),
              openssl::ellipticCurveNid::SECP_521r1);
    EXPECT_EQ(dynamic_cast<ECCSpec *>(Ed448Spec.get())->curve(), openssl::ellipticCurveNid::Ed448);
    EXPECT_EQ(dynamic_cast<ECCSpec *>(Ed25519Spec.get())->curve(),
              openssl::ellipticCurveNid::Ed25519);
    EXPECT_EQ(dynamic_cast<ECCSpec *>(defaultSpec.get())->curveName(), "P-256");
    EXPECT_EQ(dynamic_cast<ECCSpec *>(Sect571r1Spec.get())->curveName(), "B-571");
    EXPECT_EQ(dynamic_cast<ECCSpec *>(Secp521Spec.get())->curveName(), "P-521");
    /* These two curves are not working:
    openssl::ellipticCurveNid::Ed448,
    openssl::ellipticCurveNid::Ed25519
    6: unknown file: Failure
    6: C++ exception with description "error:23077074:PKCS12 routines:PKCS12_pbe_crypt:pkcs12
    cipherfinal error: 587690100" thrown in the test body.
    */
    // EXPECT_EQ(dynamic_cast<ECCSpec *>(Ed448Spec.get())->curveName(), "no-work");
    // EXPECT_EQ(dynamic_cast<ECCSpec *>(Ed25519Spec.get())->curveName(), "no-work");

    std::unique_ptr<RSASpec> defaultRSASpec(
            dynamic_cast<RSASpec *>(_rsaKeyPair.getKeySpec().release()));
    EXPECT_EQ(defaultRSASpec->numberOfBits(), 2048);
}

TEST_F(KeyHandlingTests, testGetSize)
{
    EXPECT_EQ(_rsaKeyPair.getKeySize(), 2048);
    EXPECT_EQ(_eccKeyPairDefault.getKeySize(), 256);
    EXPECT_EQ(_eccKeyPairSecp521r1.getKeySize(), 521);
    EXPECT_EQ(_eccKeyPairSect571r1.getKeySize(), 570);
    EXPECT_EQ(_Ed448KeyPair.getKeySize(), 456);
    EXPECT_EQ(_Ed25519KeyPair.getKeySize(), 256);
    auto rsaKey1024 = AsymmetricKeypair::generate(mococrw::RSASpec{1024});
    EXPECT_EQ(rsaKey1024.getKeySize(), 1024);
}

/* Test the KeySpec and the generation of keys that way */
TEST(KeySpecTest, testGeneratingRSAKeyWithDefaultParameters)
{
    RSASpec spec{};

    auto keypair = spec.generate();
    ASSERT_THAT(keypair.internal(), NotNull());
}

/* Test the KeySpec and the generation of keys that way */
TEST(KeySpecTest, testGeneratingEccKeyWithDefaultParameters)
{
    ECCSpec spec{};

    auto keypair = spec.generate();
    ASSERT_THAT(keypair.internal(), NotNull());
}

TEST(KeySpecTest, testThatDefaultParametersAreSane)
{
    RSASpec spec{};
    ASSERT_EQ(spec.numberOfBits(), 2048);

    RSASpec nonDefault{1024};
    ASSERT_EQ(nonDefault.numberOfBits(), 1024);

    ECCSpec defaultEccSpec{};
    ASSERT_EQ(defaultEccSpec.curve(), openssl::ellipticCurveNid::PRIME_256v1);

    ECCSpec nonDefaultEccSpec{openssl::ellipticCurveNid::SECT_283k1};
    ASSERT_EQ(nonDefaultEccSpec.curve(), openssl::ellipticCurveNid::SECT_283k1);
}

static std::vector<openssl::ellipticCurveNid> getEllipticCurveNids()
{
    /* Test the EC public key -> EC point -> EC public key transformation for all supported
     * curves/groups */
    std::vector<openssl::ellipticCurveNid> testData{
            openssl::ellipticCurveNid::PRIME_192v1,
            openssl::ellipticCurveNid::PRIME_256v1,
            openssl::ellipticCurveNid::SECP_224r1,
            openssl::ellipticCurveNid::SECP_384r1,
            openssl::ellipticCurveNid::SECP_521r1,
            openssl::ellipticCurveNid::SECT_283k1,
            openssl::ellipticCurveNid::SECT_283r1,
            openssl::ellipticCurveNid::SECT_409k1,
            openssl::ellipticCurveNid::SECT_409r1,
            openssl::ellipticCurveNid::SECT_571k1,
            openssl::ellipticCurveNid::SECT_571r1
            /* These two curves are not working:
            openssl::ellipticCurveNid::Ed448,
            openssl::ellipticCurveNid::Ed25519
             * Failures:
             * unknown file: Failure
             * C++ exception with description "error:23077074:PKCS12
            routines:PKCS12_pbe_crypt:pkcs12 cipherfinal
             * error: 587690100" thrown in the test body.
             * [  FAILED  ] keyGenFromPointTest/KeyGenerationFromPointTests.tests/11,
             * where GetParam() = 4-byte object <40-04 00-00> (86112 ms)
             * [ RUN      ] keyGenFromPointTest/KeyGenerationFromPointTests.tests/12
             * unknown file: Failure
             * C++ exception with description "error:2306A075:PKCS12
            routines:PKCS12_item_decrypt_d2i:pkcs12 pbe
             * crypt error: 587636853" thrown in the test body.
             * [  FAILED  ] keyGenFromPointTest/KeyGenerationFromPointTests.tests/12,
             * where GetParam() = 4-byte object <3F-04 00-00> (10410 ms)
             */

    };
    return testData;
}

void testKeyTransformation(openssl::ellipticCurveNid nid, EllipticCurvePointConversionForm form)
{
    ECCSpec keySpec{ECCSpec(nid)};
    AsymmetricKey key(keySpec.generate());

    AsymmetricPublicKey pubKeyOrig = AsymmetricPublicKey(key.internal());
    std::vector<uint8_t> point = pubKeyOrig.toECPoint(form);
    ASSERT_EQ(pubKeyOrig.getECOctetLength(form), point.size());
    AsymmetricPublicKey pubKey =
            AsymmetricPublicKey::fromECPoint(std::make_unique<ECCSpec>(nid), point);

    ASSERT_THAT(pubKey == pubKeyOrig, true);
}

void testKeyTransformation(openssl::ellipticCurveNid nid)
{
    testKeyTransformation(nid, EllipticCurvePointConversionForm::uncompressed);
    testKeyTransformation(nid, EllipticCurvePointConversionForm::compressed);
    testKeyTransformation(nid, EllipticCurvePointConversionForm::hybrid);
}

class KeyGenerationFromPointTests : public testing::TestWithParam<openssl::ellipticCurveNid>
{
};
INSTANTIATE_TEST_SUITE_P(keyGenFromPointTest,
                        KeyGenerationFromPointTests,
                        testing::ValuesIn(getEllipticCurveNids()));

TEST_P(KeyGenerationFromPointTests, tests) { testKeyTransformation(GetParam()); }
