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

#include "asymmetric_encryption.cpp"

class CryptoDataTest : public ::testing::Test{
};


/**
 * @brief Tests the CryptoData class
 * The following use-cases are covered:
 * - constructors
 * - assignment operators
 * - operator<<
 */
TEST_F(CryptoDataTest, testCryptoData)
{
    std::string inputStr{"Lorem ipsum dolor sit amet, consectetur"};
    std::vector<uint8_t> inputVec{
            0x4C, 0x6F, 0x72, 0x65, 0x6D, 0x20, 0x69, 0x70, 0x73, 0x75, 0x6D, 0x20, 0x64, 0x6F, 0x6C,
            0x6F, 0x72, 0x20, 0x73, 0x69, 0x74, 0x20, 0x61, 0x6D, 0x65, 0x74, 0x2C, 0x20, 0x63, 0x6F,
            0x6E, 0x73, 0x65, 0x63, 0x74, 0x65, 0x74, 0x75, 0x72
    };
    std::string inputHex{
            "4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e7365637465747572"
    };

    // Step 1: Tests constructor with std::string
    mococrw::AsymmetricEncryption::CryptoData sutStr(inputStr);
    EXPECT_EQ(inputStr, sutStr.toString());
    EXPECT_EQ(inputVec, sutStr.toByteArray());
    EXPECT_EQ(inputHex, sutStr.toHex());


    // Step 2: Tests constructor with std::vector
    mococrw::AsymmetricEncryption::CryptoData sutVec(inputVec);
    EXPECT_EQ(inputVec, sutVec.toByteArray());
    EXPECT_EQ(inputStr, sutVec.toString());
    EXPECT_EQ(inputHex, sutVec.toHex());

    // Step 3: Tests assignment operators
    sutVec = inputStr;
    EXPECT_EQ(inputVec, sutVec.toByteArray());
    EXPECT_EQ(inputStr, sutVec.toString());
    sutStr = inputVec;
    EXPECT_EQ(inputStr, sutVec.toString());
    EXPECT_EQ(inputVec, sutVec.toByteArray());

    // Step 4: Tests operator<<
    std::stringstream ss;
    ss << sutStr;
    EXPECT_EQ(inputStr, ss.str());
    ss.str(std::string());
    ss << sutVec;
    EXPECT_EQ(inputStr, ss.str());
}