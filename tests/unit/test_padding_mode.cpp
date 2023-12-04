/*
 * #%L
 * %%
 * Copyright (C) 2019 BMW Car IT GmbH
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
#include <fstream>
#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mococrw/private/IOUtils.h"

#include "asymmetric_crypto_ctx.cpp"

using namespace std::string_literals;

using namespace mococrw;

/// \brief Structure to hold the data set used to test the message size
struct MessageSizeDataSet
{
    MessageSizeDataSet(const std::string &message,
                       const AsymmetricPublicKey &pubKey,
                       std::shared_ptr<RSAEncryptionPadding> padding,
                       bool expectThrow)
            : message(message)
            , encryptionCtx(std::make_shared<RSAEncryptionPublicKeyCtx>(pubKey, padding))
            , expectThrow(expectThrow)
    {
    }

    std::string message;
    std::shared_ptr<EncryptionCtx> encryptionCtx;
    bool expectThrow;
};

class PaddingModeTest : public ::testing::Test,
                        public ::testing::WithParamInterface<MessageSizeDataSet>
{
public:
    static const std::vector<MessageSizeDataSet> messageSizeDataSet;
    static const AsymmetricPublicKey rsa1024bit;
    static const AsymmetricPublicKey rsa2048bit;
};

const AsymmetricPublicKey PaddingModeTest::rsa1024bit =
        mococrw::AsymmetricKeypair::generate(RSASpec(1024));
const AsymmetricPublicKey PaddingModeTest::rsa2048bit =
        mococrw::AsymmetricKeypair::generate(RSASpec(2048));

/// \brief Data set used to test the message size limits use-cases, encryption functionality
const std::vector<MessageSizeDataSet> PaddingModeTest::messageSizeDataSet{
        // PKCS, 1024-bit key, empty message
        {"", rsa1024bit, std::make_shared<PKCSPadding>(), false},
        // PKCS, 1024-bit key, max message size (117)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456",
         rsa1024bit,
         std::make_shared<PKCSPadding>(),
         false},
        // PKCS, 1024-bit key, max message size + 1 (118)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.1234567",
         rsa1024bit,
         std::make_shared<PKCSPadding>(),
         true},
        // PKCS, 2048-bit key, empty message
        {"", rsa2048bit, std::make_shared<PKCSPadding>(), false},
        // PKCS, 2048-bit key, max message size (245)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.1234",
         rsa2048bit,
         std::make_shared<PKCSPadding>(),
         false},
        // PKCS, 2048-bit key, max message size + 1 (246)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.12345",
         rsa2048bit,
         std::make_shared<PKCSPadding>(),
         true},
        // OAEP, 1024-bit key, hashing SHA256, MGF1(SHA256), empty message
        {
                "",
                rsa1024bit,
                std::make_shared<OAEPPadding>(),
                false,
        },
        // OAEP, 1024-bit key, hashing SHA256, MGF1(SHA256), max message size (62)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.1",
         rsa1024bit,
         std::make_shared<OAEPPadding>(),
         false},
        // OAEP, 1024-bit key, hashing SHA256, MGF1(SHA256), max message size + 1 (63)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.12",
         rsa1024bit,
         std::make_shared<OAEPPadding>(),
         true},
        // OAEP, 1024-bit key, hashing SHA512, MGF1(SHA256), max message size (-2)
        {"",
         rsa1024bit,
         std::make_shared<OAEPPadding>(openssl::DigestTypes::SHA512, std::make_shared<MGF1>()),
         true},
        // OAEP, 2048-bit key, hashing SHA256, MGF1(SHA256), empty message
        {"", rsa2048bit, std::make_shared<OAEPPadding>(), false},
        // OAEP, 2048-bit key, hashing SHA256, MGF1(SHA256), max message size (190)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789",
         rsa2048bit,
         std::make_shared<OAEPPadding>(),
         false},
        // OAEP, 2048-bit key, hashing SHA256, MGF1(SHA256), max message size + 1 (191)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.",
         rsa2048bit,
         std::make_shared<OAEPPadding>(),
         true},
        // OAEP, 2048-bit key, hashing SHA512, MGF1(SHA256), max message size (126)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.12345",
         rsa2048bit,
         std::make_shared<OAEPPadding>(openssl::DigestTypes::SHA512, std::make_shared<MGF1>()),
         false},
        // OAEP, 2048-bit key, hashing SHA512, MGF1(SHA256), max message size + 1 (127)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456",
         rsa2048bit,
         std::make_shared<OAEPPadding>(openssl::DigestTypes::SHA512, std::make_shared<MGF1>()),
         true},
        // NO PADDING, 1024-bit key, max message size - 1 (127)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456",
         rsa1024bit,
         std::make_shared<NoPadding>(),
         true},
        // NO PADDING, 1024-bit key, max message size (128)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.1234567",
         rsa1024bit,
         std::make_shared<NoPadding>(),
         false},
        // NO PADDING, 1024-bit key, max message size + 1 (129)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.12345679",
         rsa1024bit,
         std::make_shared<NoPadding>(),
         true},
        // NO PADDING, 2048-bit key, max message size - 1 (255)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".1234",
         rsa2048bit,
         std::make_shared<NoPadding>(),
         true},
        // NO PADDING, 2048-bit key, max message size (256)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".12345",
         rsa2048bit,
         std::make_shared<NoPadding>(),
         false},
        // NO PADDING, 2048-bit key, max message size + 1 (257)
        {".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456789.123456789.123456789.123456789.123456789"
         ".123456",
         rsa2048bit,
         std::make_shared<NoPadding>(),
         true},
};

/**
 * @brief Tests the size limits of the message to encrypt.
 *
 * The following use cases are covered:
 * - PKCS, 1024-bit key, empty message
 * - PKCS, 1024-bit key, max message size     (117)
 * - PKCS, 1024-bit key, max message size + 1 (118)
 * - PKCS, 2048-bit key, empty message
 * - PKCS, 2048-bit key, max message size     (245)
 * - PKCS, 2048-bit key, max message size + 1 (246)
 * - OAEP, 1024-bit key, hashing SHA256, MGF1(SHA256), empty message
 * - OAEP, 1024-bit key, hashing SHA256, MGF1(SHA256), max message size     (62)
 * - OAEP, 1024-bit key, hashing SHA256, MGF1(SHA256), max message size + 1 (63)
 * - OAEP, 1024-bit key, hashing SHA512, MGF1(SHA256), max message size     (-2)
 * - OAEP, 2048-bit key, hashing SHA256, MGF1(SHA256), empty message
 * - OAEP, 2048-bit key, hashing SHA256, MGF1(SHA256), max message size     (190)
 * - OAEP, 2048-bit key, hashing SHA256, MGF1(SHA256), max message size + 1 (191)
 * - OAEP, 2048-bit key, hashing SHA512, MGF1(SHA256), max message size     (126)
 * - OAEP, 2048-bit key, hashing SHA512, MGF1(SHA256), max message size + 1 (127)
 * - NO PADDING, 1024-bit key, max message size - 1 (127)
 * - NO PADDING, 1024-bit key, max message size     (128)
 * - NO PADDING, 1024-bit key, max message size + 1 (129)
 * - NO PADDING, 2048-bit key, max message size - 1 (255)
 * - NO PADDING, 2048-bit key, max message size     (256)
 * - NO PADDING, 2048-bit key, max message size + 1 (257)
 */
TEST_P(PaddingModeTest, testMessageSize)
{
    auto data = GetParam();

    std::vector<uint8_t> msg(data.message.begin(), data.message.end());
    if (data.expectThrow) {
        EXPECT_THROW(data.encryptionCtx->encrypt(msg), MoCOCrWException);
    } else {
        EXPECT_NO_THROW(data.encryptionCtx->encrypt(msg));
    }
}

INSTANTIATE_TEST_SUITE_P(testMessageSize,
                        PaddingModeTest,
                        testing::ValuesIn(PaddingModeTest::messageSizeDataSet));
