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

#include <sys/types.h>
#include <cstdint>
#include <memory>
#include <tuple>
#include <vector>

#include "dilithium.cpp"
#include "gtest/gtest.h"
#include "mococrw/dilithium.h"
#include "mococrw/key.h"
#include "mococrw/private/IOUtils.h"
#include "mococrw/util.h"

using namespace mococrw;

class DilithiumTestsSunnyDay
        : public testing::TestWithParam<
                  std::tuple<DilithiumKeyImpl::DilithiumParameterSet, std::string>>
{
};

INSTANTIATE_TEST_SUITE_P(
        ValidKeyTypesAndMessages,
        DilithiumTestsSunnyDay,
        testing::Values(
                std::make_tuple(DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM2, "Hello World"),
                std::make_tuple(DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM3, "Hello World"),
                std::make_tuple(DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM5, "Hello World"),
                std::make_tuple(DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM2,
                                "I am exactly of size 32, true!!!"),
                std::make_tuple(DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM3,
                                "I am exactly of size 32, true!!!"),
                std::make_tuple(DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM5,
                                "I am exactly of size 32, true!!!")));

void signAndVerify(const DilithiumAsymmetricPrivateKey &privKey, const std::string &messageStr)
{
    std::vector<uint8_t> message(messageStr.begin(), messageStr.end());
    auto ctx = DilithiumSigningCtx(privKey);
    auto res = ctx.signMessage(message);

    auto verify_ctx = DilithiumVerificationCtx(privKey);
    // Would throw if not successful
    verify_ctx.verifyMessage(res, message);
}

TEST_P(DilithiumTestsSunnyDay, sunnyDaySignAndVerify)
{
    auto spec = DilithiumSpec(std::get<0>(GetParam()));
    auto messageStr = std::get<1>(GetParam());

    auto priv_key = spec.generate();

    auto priv_key_ctx = DilithiumAsymmetricKeypair(priv_key._internal());
    // test getType function
    EXPECT_EQ(priv_key.getType(), AsymmetricKey::KeyTypes::DILITHIUM);
    // check if the parameter set is set correctly.
    EXPECT_EQ(priv_key._internal()->getDilithiumParameterSet(), std::get<0>(GetParam()));
    signAndVerify(priv_key_ctx, messageStr);
}

class DilithiumTests : public testing::TestWithParam<DilithiumKeyImpl::DilithiumParameterSet>
{
};
INSTANTIATE_TEST_SUITE_P(ParameterSets,
                         DilithiumTests,
                         testing::Values(DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM2,
                                         DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM3,
                                         DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM5));

TEST_P(DilithiumTests, testPublicKeyExtraction)
{
    auto spec = DilithiumSpec(GetParam());
    auto priv_key = spec.generate();

    auto pub_key_raw = priv_key._internal()->getPublicKey();
    auto pub_key = DilithiumAsymmetricPublicKey(std::make_shared<DilithiumKeyImpl>(pub_key_raw));

    EXPECT_EQ(pub_key._internal()->getPublicKey().getKeyData(), pub_key_raw.getKeyData());
}

TEST(DilithiumTest, CheckPrivateKeyGenerationWithDefaultParameterSet)
{
    auto spec = DilithiumSpec();
    auto priv_key_ctx = DilithiumAsymmetricKeypair::generate(spec);
    std::string messageStr = "You better believe, I'm loaded with both!";
    signAndVerify(priv_key_ctx, messageStr);
}

struct DerTestData
{
    std::string privateKeyDerPath;
    std::string privateKeyRawPath;
    std::string publicKeyDerPath;
    std::string publicKeyRawPath;
    std::string messagePath;
    std::string signaturePath;
};

class DilithiumTestDerData : public testing::TestWithParam<DerTestData>
{
};

INSTANTIATE_TEST_SUITE_P(TestData,
                         DilithiumTestDerData,
                         testing::Values(
                                 DerTestData{// DILITHIUM 3
                                             "dilithium3-private-key.der",
                                             "dilithium3-private-key.raw",
                                             "dilithium3-public-key.der",
                                             "dilithium3-public-key.raw",
                                             "message.raw",
                                             "dilithium3-test-signature.raw"},
                                 DerTestData{
                                         // DILITHIUM 5
                                         "dilithium5-private-key.der",
                                         "dilithium5-private-key.raw",
                                         "dilithium5-public-key.der",
                                         "dilithium5-public-key.raw",
                                         "message.raw",
                                         "dilithium5-test-signature.raw",
                                 }

                                 ));

TEST_P(DilithiumTestDerData, DerTestData)
{
    auto testData = GetParam();
    auto privKeyPkcs8 = utility::bytesFromFile<uint8_t>(testData.privateKeyDerPath);
    auto privKeyRaw = utility::bytesFromFile<uint8_t>(testData.privateKeyRawPath);

    auto pubKeyX509 = utility::bytesFromFile<uint8_t>(testData.publicKeyDerPath);
    auto pubKeyRaw = utility::bytesFromFile<uint8_t>(testData.publicKeyRawPath);

    auto message = utility::bytesFromFile<uint8_t>(testData.messagePath);
    auto signature = utility::bytesFromFile<uint8_t>(testData.signaturePath);

    // Check private key parsing
    auto privKey = DilithiumKeyImpl::readPrivateKeyFromDER(privKeyPkcs8);
    EXPECT_EQ(privKey->getKeyData(), privKeyRaw);
    auto privKeyCtx = DilithiumAsymmetricPrivateKey(privKey);
    EXPECT_EQ(privKeyCtx, DilithiumAsymmetricPrivateKey::readPrivateKeyfromDER(privKeyPkcs8));

    // Check public key parsing
    auto pubKey = DilithiumKeyImpl::readPublicKeyFromDER(pubKeyX509);
    EXPECT_EQ(pubKey->getKeyData(), pubKeyRaw);
    auto pubKeyCtx = DilithiumAsymmetricPublicKey(pubKey);
    EXPECT_EQ(pubKeyCtx, DilithiumAsymmetricPublicKey::readPublicKeyfromDER(pubKeyX509));

    // Check signature verification
    auto verificationCtx = DilithiumVerificationCtx(pubKeyCtx);
    verificationCtx.verifyMessage(signature, message);

    // Check if self-created signature is the same. (Deterministic mode is required to be enabled =
    // default)
    auto signatureCtx = DilithiumSigningCtx(privKeyCtx);
    auto mySignature = signatureCtx.signMessage(message);
    EXPECT_EQ(mySignature, signature);
}

TEST(DilithiumTests, TestInvalidKeyLength)
{
    std::vector<uint8_t> key{'h', 'e', 'l', 'l', 'o'};
    // The constructor throws if key data with invalid length is passed as argument
    EXPECT_THROW(DilithiumKeyImpl(key, DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM2, true),
                 MoCOCrWException);
}

TEST(DilithiumTests, KeyComparison)
{
    auto spec = DilithiumSpec(DilithiumKeyImpl::DilithiumParameterSet::DILITHIUM2);
    auto key = DilithiumAsymmetricKeypair::generate(spec);
    auto key2 = DilithiumAsymmetricKeypair(key);

    EXPECT_TRUE(key == key2);
    EXPECT_FALSE(key != key2);

    auto key3 = DilithiumAsymmetricKeypair::generate(spec);
    EXPECT_FALSE(key == key3);
}