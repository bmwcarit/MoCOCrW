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

#include "mococrw/error.h"
#include "mococrw/symmetric_crypto.h"
#include "mococrw/util.h"

using namespace mococrw;

using EncrytDecryptTestData = std::tuple<SymmetricCipherKeySize, SymmetricCipherMode, std::string>;

class SymmetricCipherBase
{
public:
    virtual void SetUp()
    {
        _secretKey = utility::fromHex(
                "0000000000000000000000000000000011111111111111111111111111111111");
        std::string tmp;
        for (size_t i = 0; i < 1024 + 17; i++) {
            tmp += "a string which will be concatenated multiple times-";
        }
        _plaintext = {tmp.begin(), tmp.end()};

        std::string associatedData = "This string will be authenticated.";
        _associatedData = {associatedData.begin(), associatedData.end()};
    }

    std::vector<uint8_t> _secretKey;
    std::vector<uint8_t> _plaintext;
    std::vector<uint8_t> _associatedData;
};

struct SymmetricCipherReferenceTestData
{
    SymmetricCipherMode mode;
    SymmetricCipherPadding padding;
    std::vector<uint8_t> input;
    std::vector<uint8_t> key;
    std::vector<uint8_t> iV;
    std::vector<uint8_t> authTag;
    std::vector<uint8_t> expectedOutput;
};

class SymmetricCipherReferenceTest : public testing::TestWithParam<SymmetricCipherReferenceTestData>
{
};

TEST_P(SymmetricCipherReferenceTest, decryptionMatchesReferenceImplementation)
{
    auto testData = GetParam();

    auto cipherBuilder =
            AESCipherBuilder{testData.mode, SymmetricCipherKeySize::S_256, testData.key}
                    .setIV(testData.iV)
                    .setPadding(testData.padding);
    std::shared_ptr<SymmetricCipherI> decryptor;
    if (isAuthenticatedCipherMode(testData.mode)) {
        decryptor = cipherBuilder.buildAuthenticatedDecryptor();
    } else {
        decryptor = cipherBuilder.buildDecryptor();
    }

    decryptor->update(testData.input);

    auto authenticatedDecryptor = dynamic_cast<AuthenticatedEncryptionI *>(decryptor.get());
    if (authenticatedDecryptor) {
        authenticatedDecryptor->setAuthTag(testData.authTag);
    }

    auto output = decryptor->finish();

    ASSERT_THAT(output, ::testing::ElementsAreArray(testData.expectedOutput));
}

static std::vector<SymmetricCipherReferenceTestData> prepareTestDataForReferenceDecryption()
{
    std::vector<SymmetricCipherReferenceTestData> testData{
            // https://tools.ietf.org/html/rfc3686#section-6
            {SymmetricCipherMode::CTR,
             SymmetricCipherPadding::PKCS,
             utility::fromHex("F05E231B3894612C49EE000B804EB2A9B8306B508F839D6A5530831D9344AF1C"),
             utility::fromHex("F6D66D6BD52D59BB0796365879EFF886C66DD51A5B6A99744B50590C87A23884"),
             utility::fromHex("00FAAC24C1585EF15A43D87500000001"),
             {},
             utility::fromHex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")},
            // AES GCM test vector from
            // http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
            {SymmetricCipherMode::GCM,
             SymmetricCipherPadding::PKCS,
             utility::fromHex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb0"
                              "8e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"),
             utility::fromHex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
             utility::fromHex("cafebabefacedbaddecaf888"),
             utility::fromHex("b094dac5d93471bdec1a502270e3cc6c"),
             utility::fromHex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c"
                              "0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")},
            // NIST document SP800-38A
            {SymmetricCipherMode::CBC,
             SymmetricCipherPadding::NO,
             utility::fromHex("39f23369a9d9bacfa530e26304231461"),
             utility::fromHex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
             utility::fromHex("9CFC4E967EDB808D679F777BC6702C7D"),
             {},
             utility::fromHex("30c81c46a35ce411e5fbc1191a0a52ef")}};

    return testData;
}

INSTANTIATE_TEST_SUITE_P(ReferenceDecryption,
                        SymmetricCipherReferenceTest,
                        testing::ValuesIn(prepareTestDataForReferenceDecryption()));

class SymmetricCipherTest : public SymmetricCipherBase,
                            public testing::TestWithParam<EncrytDecryptTestData>
{
    void SetUp() override { SymmetricCipherBase::SetUp(); }
};

TEST_P(SymmetricCipherTest, DoubleCreationUsesDifferentIVs)
{
    auto keySize = std::get<0>(GetParam());
    auto operationMode = std::get<1>(GetParam());
    auto plaintextString = std::get<2>(GetParam());
    auto secretKey = _secretKey;
    // resize randomly generated key to match the tested cipher
    secretKey.resize(keySize == SymmetricCipherKeySize::S_256 ? 32 : 16);
    std::vector<uint8_t> plaintext{plaintextString.begin(), plaintextString.end()};

    auto encryptorBuilder = AESCipherBuilder{operationMode, keySize, secretKey};
    std::shared_ptr<SymmetricCipherI> encryptor0, encryptor1;
    if (isAuthenticatedCipherMode(operationMode)) {
        encryptor0 = encryptorBuilder.buildAuthenticatedEncryptor();
        encryptor1 = encryptorBuilder.buildAuthenticatedEncryptor();
    } else {
        encryptor0 = encryptorBuilder.buildEncryptor();
        encryptor1 = encryptorBuilder.buildEncryptor();
    }

    auto iv0 = encryptor0->getIV();
    auto iv1 = encryptor1->getIV();
    ASSERT_NE(iv0, iv1) << "Calling buildEncryptor() twice yields the same IV!";

    encryptor0->update(plaintext);
    encryptor1->update(plaintext);

    auto ciphertext0 = encryptor0->finish();
    auto ciphertext1 = encryptor1->finish();

    if (ciphertext0.size() > 0 || ciphertext1.size() > 0) {
        if ((operationMode != SymmetricCipherMode::GCM &&
             operationMode != SymmetricCipherMode::CTR) ||
            ciphertext0.size() > 1) {
            /* Don't compare AES-GCM and AES-CTR encryptions with different IVs
             * if the ciphertext is only 1 byte. Because GCM and CTR are stream
             * ciphers, it does occasionally happen that two different IVs with
             * two different keys yield the same byte in the ciphertext. With
             * block ciphers, this is not a problem, because they always
             * produce outputs in multiples of the block size, where
             * a collision is statistically unlikely enough so that we can
             * ignore it. */
            ASSERT_NE(ciphertext0, ciphertext1) << "Two encryption operations with different IVs "
                                                   "should return different ciphertexts.";
        }
    }
}

TEST_P(SymmetricCipherTest, EncryptDecryptDifferentPlaintextLength)
{
    auto keySize = std::get<0>(GetParam());
    auto operationMode = std::get<1>(GetParam());
    auto plaintextString = std::get<2>(GetParam());
    auto secretKey = _secretKey;
    // resize randomly generated key to match the tested cipher
    secretKey.resize(keySize == SymmetricCipherKeySize::S_256 ? 32 : 16);
    std::vector<uint8_t> plaintext{plaintextString.begin(), plaintextString.end()};

    // When: encrypt and then decrypt the plaintext
    auto encryptoBuilder = AESCipherBuilder{operationMode, keySize, secretKey};
    std::shared_ptr<SymmetricCipherI> encryptor;
    if (isAuthenticatedCipherMode(operationMode)) {
        encryptor = encryptoBuilder.buildAuthenticatedEncryptor();
    } else {
        encryptor = encryptoBuilder.buildEncryptor();
    }

    encryptor->update(plaintext);
    auto ciphertext = encryptor->finish();
    auto iv = encryptor->getIV();

    std::vector<uint8_t> tag;
    // NOTE: In a real code you usually know type of the encryption in advance and hardly need
    // to cast. Here we do this to keep tests compact and improve on code reuse.
    auto authenticatedEncryptor = dynamic_cast<AuthenticatedEncryptionI *>(encryptor.get());
    if (authenticatedEncryptor) {
        tag = authenticatedEncryptor->getAuthTag();
    }

    auto decryptorBuilder = AESCipherBuilder{operationMode, keySize, secretKey}.setIV(iv);
    std::shared_ptr<SymmetricCipherI> decryptor;
    if (isAuthenticatedCipherMode(operationMode)) {
        decryptor = decryptorBuilder.buildAuthenticatedDecryptor();
    } else {
        decryptor = decryptorBuilder.buildDecryptor();
    }

    auto authenticatedDecryptor = dynamic_cast<AuthenticatedEncryptionI *>(decryptor.get());
    if (authenticatedDecryptor) {
        authenticatedDecryptor->setAuthTag(tag);
    }

    decryptor->update(ciphertext);
    auto decryptedText = decryptor->finish();

    // Then: Decrypted text should match the plaintext
    ASSERT_THAT(decryptedText, ::testing::ElementsAreArray(plaintext));
}

static std::vector<EncrytDecryptTestData> prepareTestDataForMode(SymmetricCipherMode mode)
{
    static const std::vector<std::string> PLAINTEXT_STRINGS_OF_DIFFERENT_LENGTH{
            "",  // empty string
            "0",
            "0123456789",           // less than a block
            "0123456789123456",     // a block
            "01234567891234567890"  // more than a block
    };

    static const std::vector<SymmetricCipherKeySize> SUPPORTED_KEY_SIZES{
            SymmetricCipherKeySize::S_128, SymmetricCipherKeySize::S_256};

    std::vector<EncrytDecryptTestData> testData;
    for (const auto &elem : PLAINTEXT_STRINGS_OF_DIFFERENT_LENGTH) {
        for (const auto keySize : SUPPORTED_KEY_SIZES) {
            testData.emplace_back(std::make_tuple(keySize, mode, elem));
        }
    }
    return testData;
}

INSTANTIATE_TEST_SUITE_P(GCM,
                        SymmetricCipherTest,
                        testing::ValuesIn(prepareTestDataForMode(SymmetricCipherMode::GCM)));

INSTANTIATE_TEST_SUITE_P(CBC,
                        SymmetricCipherTest,
                        testing::ValuesIn(prepareTestDataForMode(SymmetricCipherMode::CBC)));

INSTANTIATE_TEST_SUITE_P(CTR,
                        SymmetricCipherTest,
                        testing::ValuesIn(prepareTestDataForMode(SymmetricCipherMode::CTR)));

static const std::vector<SymmetricCipherMode> AllSupportedCipherModesToTest{
        SymmetricCipherMode::CBC, SymmetricCipherMode::GCM, SymmetricCipherMode::CTR};

class SymmetricCipherAdvancedTest : public SymmetricCipherBase,
                                    public testing::TestWithParam<SymmetricCipherMode>
{
    void SetUp() override { SymmetricCipherBase::SetUp(); }
};

class SymmetricCipherWrongParametersTest : public SymmetricCipherAdvancedTest
{
};

TEST_P(SymmetricCipherWrongParametersTest, throwsIfWrongIVLengthIsUsed)
{
    auto operationMode = GetParam();
    // Use IV shorter than block size
    std::vector<uint8_t> shortIv(9, 1);

    auto builder = AESCipherBuilder{operationMode, SymmetricCipherKeySize::S_256, _secretKey}.setIV(
            shortIv);
    if (isAuthenticatedCipherMode(operationMode)) {
        // For AES-GCM, variable IV length supported
    } else {
        ASSERT_THROW(builder.buildEncryptor(), MoCOCrWException);
    }
}

TEST_P(SymmetricCipherWrongParametersTest, throwsIfWrongKeyLengthIsUsed)
{
    auto operationMode = GetParam();
    // Use key shorter than AES-256 expects
    std::vector<uint8_t> shortKey(12, 1);

    auto builder = AESCipherBuilder{operationMode, SymmetricCipherKeySize::S_256, shortKey};
    ASSERT_THROW(builder.buildEncryptor(), MoCOCrWException);
}

TEST_P(SymmetricCipherWrongParametersTest, throwsIfBuilderDoesNotMatchMode)
{
    auto operationMode = GetParam();
    auto builder = AESCipherBuilder{operationMode, SymmetricCipherKeySize::S_256, _secretKey};

    if (isAuthenticatedCipherMode(operationMode)) {
        ASSERT_THROW(builder.buildEncryptor(), MoCOCrWException);
        ASSERT_THROW(builder.buildDecryptor(), MoCOCrWException);
    } else {
        ASSERT_THROW(builder.buildAuthenticatedEncryptor(), MoCOCrWException);
        ASSERT_THROW(builder.buildAuthenticatedDecryptor(), MoCOCrWException);
    }
}

INSTANTIATE_TEST_SUITE_P(AllModes,
                        SymmetricCipherWrongParametersTest,
                        testing::ValuesIn(AllSupportedCipherModesToTest));

TEST_P(SymmetricCipherAdvancedTest, encryptMultipleChunksAndDecrypt)
{
    auto operationMode = GetParam();

    // Given: long plaintext string

    // When: Read and encrypt plaintext in chunks. Then decrypt ciphertext.
    auto encryptoBuilder =
            AESCipherBuilder{operationMode, SymmetricCipherKeySize::S_256, _secretKey};
    std::shared_ptr<SymmetricCipherI> encryptor;
    if (isAuthenticatedCipherMode(operationMode)) {
        encryptor = encryptoBuilder.buildAuthenticatedEncryptor();
    } else {
        encryptor = encryptoBuilder.buildEncryptor();
    }

    size_t packetSize = 1024 * 4;
    auto packetIterator = _plaintext.begin();
    while (packetIterator < _plaintext.end() - packetSize) {
        encryptor->update({packetIterator, packetIterator + packetSize});
        packetIterator += packetSize;
    }
    encryptor->update({packetIterator, _plaintext.end()});
    auto ciphertext = encryptor->finish();
    auto iv = encryptor->getIV();
    std::vector<uint8_t> tag;
    auto authenticatedEncryptor = dynamic_cast<AuthenticatedEncryptionI *>(encryptor.get());
    if (authenticatedEncryptor) {
        tag = authenticatedEncryptor->getAuthTag();
    }

    auto decryptorBuilder =
            AESCipherBuilder{operationMode, SymmetricCipherKeySize::S_256, _secretKey}.setIV(iv);
    std::shared_ptr<SymmetricCipherI> decryptor;
    if (isAuthenticatedCipherMode(operationMode)) {
        decryptor = decryptorBuilder.buildAuthenticatedDecryptor();
    } else {
        decryptor = decryptorBuilder.buildDecryptor();
    }
    decryptor->update(ciphertext);
    auto authenticatedDecryptor = dynamic_cast<AuthenticatedEncryptionI *>(decryptor.get());
    if (authenticatedDecryptor) {
        authenticatedDecryptor->setAuthTag(tag);
    }
    auto decryptedText = decryptor->finish();

    // Then: Decrypted text should match the plaintext
    ASSERT_THAT(decryptedText, ::testing::ElementsAreArray(_plaintext));
}

TEST_P(SymmetricCipherAdvancedTest, readDecryptedTextInChunks)
{
    auto operationMode = GetParam();

    // Given: long encrypted message
    auto encryptoBuilder =
            AESCipherBuilder{operationMode, SymmetricCipherKeySize::S_256, _secretKey};
    std::shared_ptr<SymmetricCipherI> encryptor;
    if (isAuthenticatedCipherMode(operationMode)) {
        encryptor = encryptoBuilder.buildAuthenticatedEncryptor();
    } else {
        encryptor = encryptoBuilder.buildEncryptor();
    }

    encryptor->update(_plaintext);
    auto ciphertext = encryptor->finish();
    auto iv = encryptor->getIV();
    std::vector<uint8_t> tag;
    auto authenticatedEncryptor = dynamic_cast<AuthenticatedEncryptionI *>(encryptor.get());
    if (authenticatedEncryptor) {
        tag = authenticatedEncryptor->getAuthTag();
    }

    // When: decrypt in chunks
    auto decryptorBuilder =
            AESCipherBuilder{operationMode, SymmetricCipherKeySize::S_256, _secretKey}.setIV(iv);
    std::shared_ptr<SymmetricCipherI> decryptor;
    if (isAuthenticatedCipherMode(operationMode)) {
        decryptor = decryptorBuilder.buildAuthenticatedDecryptor();
    } else {
        decryptor = decryptorBuilder.buildDecryptor();
    }

    std::vector<uint8_t> decryptedText;

    // Decrypt packets and read decrypted text in chunks. Size of these chunks is different.
    static int const DECRYPTION_CHUNK_SIZE = 1024 * 4;
    static int const READ_BUFFER_SIZE = 1024;
    auto ciphertextRunner = ciphertext.begin();
    while (std::distance(ciphertextRunner, std::end(ciphertext)) > DECRYPTION_CHUNK_SIZE) {
        decryptor->update({ciphertextRunner, ciphertextRunner + DECRYPTION_CHUNK_SIZE});
        ciphertextRunner += DECRYPTION_CHUNK_SIZE;
        auto decryptedChunk = decryptor->read(READ_BUFFER_SIZE);
        decryptedText.insert(
                std::end(decryptedText), std::begin(decryptedChunk), std::end(decryptedChunk));
    }
    // Decrypt the rest which didn't fit into decryption chunk
    decryptor->update({ciphertextRunner, std::end(ciphertext)});

    auto authenticatedDecryptor = dynamic_cast<AuthenticatedEncryptionI *>(decryptor.get());
    if (authenticatedDecryptor) {
        authenticatedDecryptor->setAuthTag(tag);
    }
    auto decryptedChunkFinal = decryptor->finish();
    decryptedText.insert(std::end(decryptedText),
                         std::begin(decryptedChunkFinal),
                         std::end(decryptedChunkFinal));

    ASSERT_THAT(decryptedText, ::testing::ElementsAreArray(_plaintext));
}

INSTANTIATE_TEST_SUITE_P(Chunks,
                        SymmetricCipherAdvancedTest,
                        testing::ValuesIn(AllSupportedCipherModesToTest));

class SymmetricAuthenticatedCipherTest : public SymmetricCipherBase, public testing::Test
{
    void SetUp() override { SymmetricCipherBase::SetUp(); }
};

TEST_F(SymmetricAuthenticatedCipherTest, nonDefaultTagLength)
{
    size_t nonDefaultTagLength = 96 / 8;

    auto encryptor =
            AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, _secretKey}
                    .setAuthTagLength(nonDefaultTagLength)
                    .buildAuthenticatedEncryptor();
    encryptor->update(_plaintext);
    auto ciphertext = encryptor->finish();
    auto tag = encryptor->getAuthTag();

    ASSERT_EQ(tag.size(), nonDefaultTagLength);

    auto decryptor =
            AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, _secretKey}
                    .setIV(encryptor->getIV())
                    .buildAuthenticatedDecryptor();
    decryptor->update(ciphertext);
    decryptor->setAuthTag(tag);
    auto decryptedText = decryptor->finish();
    ASSERT_THAT(decryptedText, ::testing::ElementsAreArray(_plaintext));
}

TEST_F(SymmetricAuthenticatedCipherTest, nonDefaultIvLength)
{
    size_t nonDefaultIVLength = 96 / 8;
    auto iv = utility::cryptoRandomBytes(nonDefaultIVLength);

    auto encryptor =
            AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, _secretKey}
                    .setIV(iv)
                    .buildAuthenticatedEncryptor();
    encryptor->update(_plaintext);
    auto ciphertext = encryptor->finish();
    auto tag = encryptor->getAuthTag();

    ASSERT_THAT(encryptor->getIV(), ::testing::ElementsAreArray(iv));

    auto decryptor =
            AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, _secretKey}
                    .setIV(iv)
                    .buildAuthenticatedDecryptor();
    decryptor->update(ciphertext);
    decryptor->setAuthTag(tag);
    auto decryptedText = decryptor->finish();
    ASSERT_THAT(decryptedText, ::testing::ElementsAreArray(_plaintext));
}

TEST_F(SymmetricAuthenticatedCipherTest, throwsWhenCiphertextWasModified)
{
    auto encryptor =
            AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, _secretKey}
                    .buildAuthenticatedEncryptor();

    encryptor->update(_plaintext);
    auto ciphertext = encryptor->finish();
    auto tag = encryptor->getAuthTag();

    // flip a bit in authenticated ciphertext
    ciphertext[4] ^= 1;

    auto decryptor =
            AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, _secretKey}
                    .setIV(encryptor->getIV())
                    .buildAuthenticatedDecryptor();
    decryptor->update(ciphertext);
    decryptor->setAuthTag(tag);

    ASSERT_THROW(decryptor->finish(), MoCOCrWException);
}

TEST_F(SymmetricAuthenticatedCipherTest, throwsWhenWrongTagIsUsed)
{
    auto encryptor =
            AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, _secretKey}
                    .buildAuthenticatedEncryptor();

    encryptor->update(_plaintext);
    auto ciphertext = encryptor->finish();
    auto tag = encryptor->getAuthTag();

    // flip a bit in the tag
    tag[4] ^= 1;

    auto decryptor =
            AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, _secretKey}
                    .setIV(encryptor->getIV())
                    .buildAuthenticatedDecryptor();
    decryptor->update(ciphertext);
    decryptor->setAuthTag(tag);

    ASSERT_THROW(decryptor->finish(), MoCOCrWException);
}

TEST_F(SymmetricAuthenticatedCipherTest, authenticatesAssociatedData)
{
    auto encryptor =
            AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, _secretKey}
                    .buildAuthenticatedEncryptor();

    encryptor->addAssociatedData(_associatedData);
    encryptor->update(_plaintext);
    auto ciphertext = encryptor->finish();
    auto tag = encryptor->getAuthTag();

    auto decryptor =
            AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, _secretKey}
                    .setIV(encryptor->getIV())
                    .buildAuthenticatedDecryptor();

    decryptor->addAssociatedData(_associatedData);
    decryptor->update(ciphertext);
    decryptor->setAuthTag(tag);
    auto decryptedText = decryptor->finish();
    ASSERT_THAT(decryptedText, ::testing::ElementsAreArray(_plaintext));
}

TEST_F(SymmetricAuthenticatedCipherTest, throwsIfaddAssociatedDataCalledAfterUpdate)
{
    auto encryptor =
            AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, _secretKey}
                    .buildAuthenticatedEncryptor();

    encryptor->update(_plaintext);
    ASSERT_THROW(encryptor->addAssociatedData(_associatedData), MoCOCrWException);
}

TEST_F(SymmetricAuthenticatedCipherTest, throwsIfAssociatedDataMissingOrModified)
{
    auto encryptor =
            AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, _secretKey}
                    .buildAuthenticatedEncryptor();

    encryptor->addAssociatedData(_associatedData);
    encryptor->update(_plaintext);
    auto ciphertext = encryptor->finish();
    auto tag = encryptor->getAuthTag();

    auto decryptor =
            AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, _secretKey}
                    .setIV(encryptor->getIV())
                    .buildAuthenticatedDecryptor();
    decryptor->setAuthTag(tag);
    _associatedData[2] ^= 1;
    decryptor->addAssociatedData(_associatedData);
    decryptor->update(ciphertext);

    ASSERT_THROW(decryptor->finish(), MoCOCrWException);

    auto decryptor2 =
            AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, _secretKey}
                    .setIV(encryptor->getIV())
                    .buildAuthenticatedDecryptor();
    decryptor2->setAuthTag(tag);
    decryptor2->update(ciphertext);

    ASSERT_THROW(decryptor2->finish(), MoCOCrWException);
}

TEST_F(SymmetricAuthenticatedCipherTest, cipherTextSameWithAndWithoutAssociatedData)
{
    const std::vector<uint8_t> iv = utility::fromHex("db0a66d2e812a3416c72f9c10280d100");
    auto aesCipherBuilder =
            AESCipherBuilder{SymmetricCipherMode::GCM, SymmetricCipherKeySize::S_256, _secretKey}
                    .setIV(iv);

    auto encryptor1 = aesCipherBuilder.buildAuthenticatedEncryptor();
    encryptor1->addAssociatedData(_associatedData);
    encryptor1->update(_plaintext);
    auto ciphertext1 = encryptor1->finish();

    auto encryptor2 = aesCipherBuilder.buildAuthenticatedEncryptor();
    encryptor2->update(_plaintext);
    auto ciphertext2 = encryptor2->finish();

    ASSERT_EQ(ciphertext1, ciphertext2);
}
