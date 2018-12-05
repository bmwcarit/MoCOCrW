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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <functional>

#include "hash.cpp"
#include "util.cpp"
#include "mococrw/error.h"

using namespace mococrw;

using testing::Eq;

class HashTest : public ::testing::Test
{
};

const auto sha1_emptyString = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
const auto sha1_foo = "0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33";
const auto sha1_foobar = "8843d7f92416211de9ebb963ff4ce28125932878";

const auto sha256_emptyString = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const auto sha256_foo = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
const auto sha256_foobar = "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2";

const auto sha384_emptyString = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
const auto sha384_foo = "98c11ffdfdd540676b1a137cb1a22b2a70350c9a44171d6b1180c6be5cbb2ee3f79d532c8a1dd9ef2e8e08e752a3babb";
const auto sha384_foobar = "3c9c30d9f665e74d515c842960d4a451c83a0125fd3de7392d7b37231af10c72ea58aedfcdf89a5765bf902af93ecf06";

const auto sha512_emptyString = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
const auto sha512_foo = "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7";
const auto sha512_foobar = "0a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219337f81616a8069b012587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425";

TEST_F(HashTest, sha1EmptyString)
{
    EXPECT_THAT(utility::toHex(Hash::sha1().digest()), Eq(sha1_emptyString));
}

TEST_F(HashTest, sha256EmptyString)
{
    EXPECT_THAT(utility::toHex(Hash::sha256().digest()), Eq(sha256_emptyString));
}

TEST_F(HashTest, sha384EmptyString)
{
    EXPECT_THAT(utility::toHex(Hash::sha384().digest()), Eq(sha384_emptyString));
}

TEST_F(HashTest, sha512EmptyString)
{
    EXPECT_THAT(utility::toHex(Hash::sha512().digest()), Eq(sha512_emptyString));
}

TEST_F(HashTest, sha1SingleUpdateString)
{
    EXPECT_THAT(utility::toHex(Hash::sha1().update("foo").digest()), Eq(sha1_foo));
}

TEST_F(HashTest, sha256SingleUpdateString)
{
    EXPECT_THAT(utility::toHex(Hash::sha256().update("foo").digest()), Eq(sha256_foo));
}

TEST_F(HashTest, sha384SingleUpdateString)
{
    EXPECT_THAT(utility::toHex(Hash::sha384().update("foo").digest()), Eq(sha384_foo));
}

TEST_F(HashTest, sha512SingleUpdateString)
{
    EXPECT_THAT(utility::toHex(Hash::sha512().update("foo").digest()), Eq(sha512_foo));
}

TEST_F(HashTest, sha1MultipleUpdatesString)
{
    EXPECT_THAT(utility::toHex(Hash::sha1().update("foo").update("bar").digest()),
                Eq(sha1_foobar));
}

TEST_F(HashTest, sha256MultipleUpdatesString)
{
    EXPECT_THAT(utility::toHex(Hash::sha256().update("foo").update("bar").digest()),
                Eq(sha256_foobar));
}

TEST_F(HashTest, sha384MultipleUpdatesString)
{
    EXPECT_THAT(utility::toHex(Hash::sha384().update("foo").update("bar").digest()),
                Eq(sha384_foobar));
}

TEST_F(HashTest, sha512MultipleUpdatesString)
{
    EXPECT_THAT(utility::toHex(Hash::sha512().update("foo").update("bar").digest()),
                Eq(sha512_foobar));
}

TEST_F(HashTest, sha1SingleUpdateBinaryArray)
{
    EXPECT_THAT(utility::toHex(Hash::sha1().update(reinterpret_cast<const uint8_t*>(&"foo"[0]), 3).digest()),
                Eq(sha1_foo));
}

TEST_F(HashTest, sha256SingleUpdateBinaryArray)
{
    EXPECT_THAT(utility::toHex(Hash::sha256().update(reinterpret_cast<const uint8_t*>(&"foo"[0]), 3).digest()),
                Eq(sha256_foo));
}

TEST_F(HashTest, sha384SingleUpdateBinaryArray)
{
    EXPECT_THAT(utility::toHex(Hash::sha384().update(reinterpret_cast<const uint8_t*>(&"foo"[0]), 3).digest()),
                Eq(sha384_foo));
}

TEST_F(HashTest, sha512SingleUpdateBinaryArray)
{
    EXPECT_THAT(utility::toHex(Hash::sha512().update(reinterpret_cast<const uint8_t*>(&"foo"[0]), 3).digest()),
                Eq(sha512_foo));
}

TEST_F(HashTest, sha1SingleUpdateVector)
{
    std::string chunk = "foo";
    std::vector<uint8_t> chunk2conv(chunk.begin(), chunk.end());
    std::vector<uint8_t> value = Hash::sha1().update(chunk2conv).digest();
    EXPECT_THAT(utility::toHex(value), Eq(sha1_foo));
}

TEST_F(HashTest, sha256SingleUpdateVector)
{
    std::string chunk = "foo";
    std::vector<uint8_t> chunk2conv(chunk.begin(), chunk.end());
    std::vector<uint8_t> value = Hash::sha256().update(chunk2conv).digest();
    EXPECT_THAT(utility::toHex(value), Eq(sha256_foo));
}

TEST_F(HashTest, sha384SingleUpdateVector)
{
    std::string chunk = "foo";
    std::vector<uint8_t> chunk2conv(chunk.begin(), chunk.end());
    std::vector<uint8_t> value = Hash::sha384().update(chunk2conv).digest();
    EXPECT_THAT(utility::toHex(value), Eq(sha384_foo));
}

TEST_F(HashTest, sha512SingleUpdateVector)
{
    std::string chunk = "foo";
    std::vector<uint8_t> chunk2conv(chunk.begin(), chunk.end());
    std::vector<uint8_t> value = Hash::sha512().update(chunk2conv).digest();
    EXPECT_THAT(utility::toHex(value), Eq(sha512_foo));
}

TEST_F(HashTest, sha1StandaloneFunctionVectorVersion)
{
    std::string message = "foo";
    std::vector<uint8_t> messageConv(message.begin(), message.end());
    std::vector<uint8_t> digest = sha1(messageConv);
    EXPECT_THAT(utility::toHex(digest), Eq(sha1_foo));
}

TEST_F(HashTest, sha256StandaloneFunctionVectorVersion)
{
    std::string message = "foo";
    std::vector<uint8_t> messageConv(message.begin(), message.end());
    std::vector<uint8_t> digest = sha256(messageConv);
    EXPECT_THAT(utility::toHex(digest), Eq(sha256_foo));
}

TEST_F(HashTest, sha384StandaloneFunctionVectorVersion)
{
    std::string message = "foo";
    std::vector<uint8_t> messageConv(message.begin(), message.end());
    std::vector<uint8_t> digest = sha384(messageConv);
    EXPECT_THAT(utility::toHex(digest), Eq(sha384_foo));
}

TEST_F(HashTest, sha512StandaloneFunctionVectorVersion)
{
    std::string message = "foo";
    std::vector<uint8_t> messageConv(message.begin(), message.end());
    std::vector<uint8_t> digest = sha512(messageConv);
    EXPECT_THAT(utility::toHex(digest), Eq(sha512_foo));
}

TEST_F(HashTest, sha1StandaloneFunctionBinaryVersion)
{
    std::string message = "foo";
    std::vector<uint8_t> digest = sha1(reinterpret_cast<const uint8_t*>(message.c_str()), message.length());
    EXPECT_THAT(utility::toHex(digest), Eq(sha1_foo));
}

TEST_F(HashTest, sha256StandaloneFunctionBinaryVersion)
{
    std::string message = "foo";
    std::vector<uint8_t> digest = sha256(reinterpret_cast<const uint8_t*>(message.c_str()), message.length());
    EXPECT_THAT(utility::toHex(digest), Eq(sha256_foo));
}

TEST_F(HashTest, sha384StandaloneFunctionBinaryVersion)
{
    std::string message = "foo";
    std::vector<uint8_t> digest = sha384(reinterpret_cast<const uint8_t*>(message.c_str()), message.length());
    EXPECT_THAT(utility::toHex(digest), Eq(sha384_foo));
}

TEST_F(HashTest, sha512StandaloneFunctionBinaryVersion)
{
    std::string message = "foo";
    std::vector<uint8_t> digest = sha512(reinterpret_cast<const uint8_t*>(message.c_str()), message.length());
    EXPECT_THAT(utility::toHex(digest), Eq(sha512_foo));
}

TEST_F(HashTest, sha1StandaloneFunctionStringVersion)
{
    std::vector<uint8_t> digest = sha1("foo");
    EXPECT_THAT(utility::toHex(digest), Eq(sha1_foo));
}

TEST_F(HashTest, sha256StandaloneFunctionStringVersion)
{
    std::vector<uint8_t> digest = sha256("foo");
    EXPECT_THAT(utility::toHex(digest), Eq(sha256_foo));
}

TEST_F(HashTest, sha384StandaloneFunctionStringVersion)
{
    std::vector<uint8_t> digest = sha384("foo");
    EXPECT_THAT(utility::toHex(digest), Eq(sha384_foo));
}

TEST_F(HashTest, sha512StandaloneFunctionStringVersion)
{
    std::vector<uint8_t> digest = sha512("foo");
    EXPECT_THAT(utility::toHex(digest), Eq(sha512_foo));
}

TEST_F(HashTest, returnsDigestIfCalledTwice) {
    Hash hash = Hash::sha256();
    std::vector<uint8_t> digest1 = hash.digest();
    std::vector<uint8_t> digest2 = hash.digest();
    EXPECT_THAT(digest1, Eq(digest2));
}

TEST_F(HashTest, throwsIfCalledUpdateAfterDigest)
{
    std::string value;
    Hash sha256 = Hash::sha256();
    sha256.update("foo");
    sha256.digest();

    EXPECT_THROW({
        sha256.update("bar");
    }, MoCOCrWException);
}
