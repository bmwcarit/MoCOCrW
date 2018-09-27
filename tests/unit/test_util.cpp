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

void UtilTest::SetUp()
{
}

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
