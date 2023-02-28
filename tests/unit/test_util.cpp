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

#include "util.cpp"

using testing::Eq;

class UtilTest : public ::testing::Test
{
public:
    void SetUp() override;
};

void UtilTest::SetUp() {}

TEST_F(UtilTest, toHexLessThanSixteen)
{
    std::vector<uint8_t> input;
    input.push_back(0x01);
    EXPECT_THAT(mococrw::utility::toHex(input), Eq("01"));
}

TEST_F(UtilTest, toHexWithConsequentZeroes)
{
    std::vector<uint8_t> input;
    input.push_back(0x60);
    input.push_back(0x45);
    input.push_back(0x69);
    input.push_back(0xf7);
    input.push_back(0x00);
    input.push_back(0x11);
    input.push_back(0xab);
    EXPECT_THAT(mococrw::utility::toHex(input), Eq("604569f70011ab"));
}

TEST_F(UtilTest, testFromHex)
{
    std::vector<uint8_t> result;
    ASSERT_NO_THROW(result = mococrw::utility::fromHex("0x"));
    ASSERT_TRUE(result.empty());

    ASSERT_NO_THROW(result = mococrw::utility::fromHex("0x1"));
    ASSERT_THAT(result, Eq(std::vector<uint8_t>{1}));

    ASSERT_NO_THROW(result = mococrw::utility::fromHex("1"));
    ASSERT_THAT(result, Eq(std::vector<uint8_t>{1}));

    ASSERT_THROW(result = mococrw::utility::fromHex("0xabdefg"), mococrw::MoCOCrWException);
    ASSERT_THROW(result = mococrw::utility::fromHex("xyz"), mococrw::MoCOCrWException);

    std::vector<uint8_t> expectedResult = {222, 173, 190, 239};
    ASSERT_NO_THROW(result = mococrw::utility::fromHex("deadbeef"));
    ASSERT_THAT(result, Eq(expectedResult));

    ASSERT_NO_THROW(result = mococrw::utility::fromHex("0xdeadbeef"));
    ASSERT_THAT(result, Eq(expectedResult));

    ASSERT_THROW(result = mococrw::utility::fromHex("  0xdeadbeef"), mococrw::MoCOCrWException);

    ASSERT_THROW(result = mococrw::utility::fromHex("  deadbeef"), mococrw::MoCOCrWException);
}

TEST_F(UtilTest, stringCleanse)
{
    std::string secret{"1234"};
    mococrw::utility::stringCleanse(secret);
    ASSERT_EQ(0, secret.size());
}

TEST_F(UtilTest, stringCleanseCheckMemory)
{
    std::string secret{"1234"};
    auto secretPtr = &secret[0];
    auto secretSize = secret.size();
    std::string zeroedOutString(secretSize, '\0');
    mococrw::utility::stringCleanse(secret);
    // Capacity of std::string may change, depending on implementation.
    // Only test this if the memory is still allocated.
    if (secret.capacity() >= secretSize) {
        ASSERT_EQ(0, memcmp(secretPtr, &zeroedOutString[0], secretSize));
    }
}

TEST_F(UtilTest, vectorCleanse)
{
    std::vector<uint8_t> secret = {222, 173, 190, 239};
    mococrw::utility::vectorCleanse(secret);
    ASSERT_EQ(0, secret.size());
}

TEST_F(UtilTest, vectorCleanseCheckMemory)
{
    std::vector<uint8_t> secret = {222, 173, 190, 239};
    auto secretPtr = &secret[0];
    auto secretSize = secret.size();
    std::vector<uint8_t> zeroedOutVector(secretSize, 0);
    mococrw::utility::vectorCleanse(secret);
    ASSERT_EQ(0, memcmp(secretPtr, &zeroedOutVector[0], secretSize));
}
