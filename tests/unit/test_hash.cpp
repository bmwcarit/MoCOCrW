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

#include "hash.cpp"

using namespace mococrw;

using testing::Eq;

class HashTest : public ::testing::Test
{
public:
    void SetUp() override;
};

void HashTest::SetUp()
{
}

std::string toHex (unsigned char* input, int length) {
    std::stringstream result;
    for(int i = 0; i < length; i++) {
        result << std::hex << (int)input[i];
    }
    return result.str();
}

const auto sha256_emptyString = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const auto sha256_foo = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";
const auto sha256_foobar = "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2";

const auto sha256ByteLength = 256 / 8;

TEST_F(HashTest, calculatesSha256OfEmptyString)
{
    auto sha256 = Hash::sha256();
    unsigned char value[sha256ByteLength];
    sha256.digest(value);
    auto expectedValue = toHex(value, sha256ByteLength);
    EXPECT_THAT(expectedValue, Eq(sha256_emptyString));
}

TEST_F(HashTest, calculatesSha256WithOneUpdate)
{
    auto sha256 = Hash::sha256();
    sha256.update("foo");
    unsigned char value[sha256ByteLength];
    sha256.digest(value);
    auto expectedValue = toHex(value, sha256ByteLength);
    EXPECT_THAT(expectedValue, Eq(sha256_foo));
}

TEST_F(HashTest, calculatesSha256WithMultipleUpdates)
{
    auto sha256 = Hash::sha256();
    sha256.update("foo");
    sha256.update("bar");
    unsigned char value[sha256ByteLength];
    sha256.digest(value);
    auto expectedValue = toHex(value, sha256ByteLength);
    EXPECT_THAT(expectedValue, Eq(sha256_foobar));
}



