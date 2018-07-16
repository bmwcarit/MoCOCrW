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

const auto sha256_emptyString = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const auto sha512_emptyString = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
const auto sha256_foo = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
const auto sha256_foobar = "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2";

TEST_F(HashTest, sha256EmptyString)
{
    EXPECT_THAT(utility::toHex(Hash::sha256().digest()), Eq(sha256_emptyString));
}

TEST_F(HashTest, sha512EmptyString)
{
    EXPECT_THAT(utility::toHex(Hash::sha512().digest()), Eq(sha512_emptyString));
}

TEST_F(HashTest, sha256SingleUpdateString)
{
    EXPECT_THAT(utility::toHex(Hash::sha256().update("foo").digest()), Eq(sha256_foo));
}

TEST_F(HashTest, sha256MultipleUpdatesString)
{
    EXPECT_THAT(utility::toHex(Hash::sha256().update("foo").update("bar").digest()),
                Eq(sha256_foobar));
}

TEST_F(HashTest, sha256SingleUpdateBinaryArray)
{
    EXPECT_THAT(utility::toHex(Hash::sha256().update(reinterpret_cast<const uint8_t*>(&"foo"[0]), 3).digest()),
                Eq(sha256_foo));
}

TEST_F(HashTest, sha256SingleUpdateVector)
{
    std::string chunk = "foo";
    std::vector<uint8_t> chunk2conv(chunk.begin(), chunk.end());
    std::vector<uint8_t> value = Hash::sha256().update(chunk2conv).digest();
    EXPECT_THAT(utility::toHex(value), Eq(sha256_foo));
}

TEST_F(HashTest, sha256StandaloneFunctionVectorVersion)
{
    std::string message = "foo";
    std::vector<uint8_t> messageConv(message.begin(), message.end());
    std::vector<uint8_t> digest = sha256(messageConv);
    EXPECT_THAT(utility::toHex(digest), Eq(sha256_foo));
}

TEST_F(HashTest, sha256StandaloneFunctionBinaryVersion)
{
    std::string message = "foo";
    std::vector<uint8_t> digest = sha256(reinterpret_cast<const uint8_t*>(message.c_str()), message.length());
    EXPECT_THAT(utility::toHex(digest), Eq(sha256_foo));
}

TEST_F(HashTest, sha256StandaloneFunctionStringVersion)
{
    std::vector<uint8_t> digest = sha256("foo");
    EXPECT_THAT(utility::toHex(digest), Eq(sha256_foo));
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
