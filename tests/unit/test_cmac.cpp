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
#include "util.cpp"

#include "mococrw/mac.h"

using namespace mococrw;

using testing::Eq;

TEST(CheckConstructor, FailsForInvalidKey)
{
    std::vector<uint8_t> invalidKey{1, 2, 3};
    auto someCipher = openssl::CmacCipherTypes::AES_CBC_256;

    EXPECT_THROW(CMAC(someCipher, invalidKey), MoCOCrWException);
}

TEST(CheckConstructor, WorksWithValidCipherAndMatchingKey)
{
    std::vector<uint8_t> someKey(16);
    auto someCipher = openssl::CmacCipherTypes::AES_CBC_128;

    CMAC(someCipher, someKey);
}

struct Testdata
{
    openssl::CmacCipherTypes cipherType;
    std::string key;
    std::string message;
    std::string expectedCmac;
};

static std::vector<Testdata> prepareTestdataForCmacTests()
{
    std::vector<Testdata> testdata{{
            // Test data for AES-128 is taken from https://tools.ietf.org/html/rfc4493.
            {
                    openssl::CmacCipherTypes::AES_CBC_128,
                    "2b7e151628aed2a6abf7158809cf4f3c",
                    "",
                    "bb1d6929e95937287fa37d129b756746",
            },
            {
                    openssl::CmacCipherTypes::AES_CBC_128,
                    "2b7e151628aed2a6abf7158809cf4f3c",
                    "6bc1bee22e409f96e93d7e117393172a",
                    "070a16b46b4d4144f79bdd9dd04a287c",
            },
            {
                    openssl::CmacCipherTypes::AES_CBC_128,
                    "2b7e151628aed2a6abf7158809cf4f3c",
                    "6bc1bee22e409f96e93d7e117393172a"
                    "ae2d8a571e03ac9c9eb76fac45af8e51"
                    "30c81c46a35ce411",
                    "dfa66747de9ae63030ca32611497c827",
            },
            {
                    openssl::CmacCipherTypes::AES_CBC_128,
                    "2b7e151628aed2a6abf7158809cf4f3c",
                    "6bc1bee22e409f96e93d7e117393172a"
                    "ae2d8a571e03ac9c9eb76fac45af8e51"
                    "30c81c46a35ce411e5fbc1191a0a52ef"
                    "f69f2445df4f9b17ad2b417be66c3710",
                    "51f0bebf7e3b9d92fc49741779363cfe",
            },

            // Test data for AES-256.
            {
                    openssl::CmacCipherTypes::AES_CBC_256,
                    "2b7e151628aed2a6abf7158809cf4f3c"
                    "deadbeef38317deafbeef3831700cafe",
                    "",
                    "9922123e226ee972e5fd501e45cae51d",
            },
            {
                    openssl::CmacCipherTypes::AES_CBC_256,
                    "2b7e151628aed2a6abf7158809cf4f3c"
                    "deadbeef38317deafbeef3831700cafe",
                    "6bc1bee22e409f96e93d7e117393172a",
                    "9414636aa65c795a59e8813e2fbb588a",
            },
            {
                    openssl::CmacCipherTypes::AES_CBC_256,
                    "2b7e151628aed2a6abf7158809cf4f3c"
                    "deadbeef38317deafbeef3831700cafe",
                    "6bc1bee22e409f96e93d7e117393172a"
                    "ae2d8a571e03ac9c9eb76fac45af8e51"
                    "30c81c46a35ce411",
                    "bf20027ad24e648f88d7cf0d2eb03f93",
            },
            {
                    openssl::CmacCipherTypes::AES_CBC_256,
                    "2b7e151628aed2a6abf7158809cf4f3c"
                    "deadbeef38317deafbeef3831700cafe",
                    "6bc1bee22e409f96e93d7e117393172a"
                    "ae2d8a571e03ac9c9eb76fac45af8e51"
                    "30c81c46a35ce411e5fbc1191a0a52ef"
                    "f69f2445df4f9b17ad2b417be66c3710",
                    "3598968688288d17a2f5544cef0651ea",
            },
    }};

    return testdata;
}

class CalculateCmacValues : public testing::TestWithParam<Testdata>
{
};

INSTANTIATE_TEST_SUITE_P(cmac,
                        CalculateCmacValues,
                        testing::ValuesIn(prepareTestdataForCmacTests()));

TEST_P(CalculateCmacValues, returnsCorrectCmac)
{
    auto testdata = GetParam();

    auto cmacCalculator = CMAC(testdata.cipherType, utility::fromHex(testdata.key));
    cmacCalculator.update(utility::fromHex(testdata.message));
    auto actualCmac = cmacCalculator.finish();

    ASSERT_THAT(utility::toHex(actualCmac), Eq(testdata.expectedCmac));
}

TEST_P(CalculateCmacValues, verifyIsSuccessfulForCorrectCmac)
{
    auto testdata = GetParam();

    auto cmacCalculator = CMAC(testdata.cipherType, utility::fromHex(testdata.key));
    cmacCalculator.update(utility::fromHex(testdata.message));
    cmacCalculator.finish();

    auto expectedCmac = utility::fromHex(testdata.expectedCmac);
    cmacCalculator.verify(expectedCmac);
}

TEST_P(CalculateCmacValues, verifyFailsForIncorrectCmac)
{
    auto testdata = GetParam();

    auto cmacCalculator = CMAC(testdata.cipherType, utility::fromHex(testdata.key));
    cmacCalculator.update(utility::fromHex(testdata.message));
    cmacCalculator.finish();

    auto incorrectCmac = utility::fromHex(testdata.expectedCmac);
    incorrectCmac[0] ^= 0x01;
    EXPECT_THROW(cmacCalculator.verify(incorrectCmac), MoCOCrWException);
}

TEST(CheckControlFlow, UpdateCanBeInvokedMultipleTimes)
{
    auto testdata = prepareTestdataForCmacTests().at(0);
    auto cmacCalculator = CMAC(testdata.cipherType, utility::fromHex(testdata.key));

    cmacCalculator.update(utility::fromHex(testdata.message));
    cmacCalculator.update(utility::fromHex(testdata.message));
}

TEST(CheckControlFlow, VerifyCanBeInvokedMultipleTimes)
{
    auto testdata = prepareTestdataForCmacTests().at(0);
    auto cmacCalculator = CMAC(testdata.cipherType, utility::fromHex(testdata.key));
    cmacCalculator.update(utility::fromHex(testdata.message));
    cmacCalculator.verify(utility::fromHex(testdata.expectedCmac));

    cmacCalculator.verify(utility::fromHex(testdata.expectedCmac));
}

TEST(CheckControlFlow, VerifyInvokesFinishImplicitly)
{
    auto testdata = prepareTestdataForCmacTests().at(0);
    auto cmacCalculator = CMAC(testdata.cipherType, utility::fromHex(testdata.key));
    cmacCalculator.update(utility::fromHex(testdata.message));
    cmacCalculator.verify(utility::fromHex(testdata.expectedCmac));

    ASSERT_THROW(cmacCalculator.finish(), MoCOCrWException);
}

TEST(CheckControlFlow, UpdateFailesAfterFinish)
{
    auto testdata = prepareTestdataForCmacTests().at(0);
    auto cmacCalculator = CMAC(testdata.cipherType, utility::fromHex(testdata.key));
    cmacCalculator.update(utility::fromHex(testdata.message));
    cmacCalculator.finish();

    ASSERT_THROW(cmacCalculator.update(utility::fromHex(testdata.message)), MoCOCrWException);
}

class VerifyCmac : public testing::Test
{
protected:
    CMAC getCmacCalculator()
    {
        auto cmacCalculator = CMAC(testdata.cipherType, utility::fromHex(testdata.key));
        cmacCalculator.update(utility::fromHex(testdata.message));
        cmacCalculator.finish();
        return cmacCalculator;
    }

    Testdata testdata = prepareTestdataForCmacTests().at(0);
};

TEST_F(VerifyCmac, FailsForTooShortCmac)
{
    auto cmacCalculator = getCmacCalculator();
    auto tooShortCmac = utility::fromHex(testdata.expectedCmac);
    tooShortCmac.resize(tooShortCmac.size() - 2);

    EXPECT_THROW(cmacCalculator.verify(tooShortCmac), MoCOCrWException);
}

TEST_F(VerifyCmac, FailsForTooLongCmac)
{
    auto cmacCalculator = getCmacCalculator();
    auto tooLongCmac = utility::fromHex(testdata.expectedCmac);
    tooLongCmac.push_back(5);

    EXPECT_THROW(cmacCalculator.verify(tooLongCmac), MoCOCrWException);
}
