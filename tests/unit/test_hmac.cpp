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

#include "mococrw/error.h"
#include "mococrw/hash.h"
#include "mococrw/mac.h"

using namespace mococrw;

using testing::Eq;

struct inputData
{
    std::string key;
    std::string data;
    size_t outputLength;
    std::string expectedResultSha256;
    std::string expectedResultSha384;
    std::string expectedResultSha512;
};

void testHmacSha(openssl::DigestTypes hashFunction, inputData testData, std::string expectedResult)
{
    /* Calculate the HMAC */
    auto hmac = mococrw::HMAC(hashFunction, utility::fromHex(testData.key));
    hmac.update(utility::fromHex(testData.data));
    auto result = hmac.finish();

    /* Check for equality */
    ASSERT_THAT(utility::toHex(result), Eq(expectedResult));

    /* Generate random value and try to verify (exception expected) */
    std::vector<uint8_t> wrongResult(utility::fromHex(expectedResult).size());
    std::generate(wrongResult.begin(), wrongResult.end(), std::rand);
    EXPECT_THROW(hmac.verify(wrongResult), MoCOCrWException);

    /* Check the verify function */
    std::vector<uint8_t> expected = utility::fromHex(expectedResult);
    hmac.verify(expected);
}

void testHmac(struct inputData testData)
{
    testHmacSha(openssl::DigestTypes::SHA256, testData, testData.expectedResultSha256);
    testHmacSha(openssl::DigestTypes::SHA384, testData, testData.expectedResultSha384);
    testHmacSha(openssl::DigestTypes::SHA512, testData, testData.expectedResultSha512);
}

static std::vector<inputData> prepareTestDataForHmacTests()
{
    /* Test data is taken from https://tools.ietf.org/html/rfc4231 */
    std::vector<inputData> testData{{{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
                                      "0b0b0b0b",
                                      "4869205468657265",
                                      0,
                                      "b0344c61d8db38535ca8afceaf0bf12b"
                                      "881dc200c9833da726e9376c2e32cff7",
                                      "afd03944d84895626b0825f4ab46907f"
                                      "15f9dadbe4101ec682aa034c7cebc59c"
                                      "faea9ea9076ede7f4af152e8b2fa9cb6",
                                      "87aa7cdea5ef619d4ff0b4241a1d6cb0"
                                      "2379f4e2ce4ec2787ad0b30545e17cde"
                                      "daa833b7d6b8a702038b274eaea3f4e4"
                                      "be9d914eeb61f1702e696c203a126854"},
                                     {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                      "aaaaaa",
                                      "54686973206973206120746573742075"
                                      "73696e672061206c6172676572207468"
                                      "616e20626c6f636b2d73697a65206b65"
                                      "7920616e642061206c61726765722074"
                                      "68616e20626c6f636b2d73697a652064"
                                      "6174612e20546865206b6579206e6565"
                                      "647320746f2062652068617368656420"
                                      "6265666f7265206265696e6720757365"
                                      "642062792074686520484d414320616c"
                                      "676f726974686d2e",
                                      0,
                                      "9b09ffa71b942fcb27635fbcd5b0e944"
                                      "bfdc63644f0713938a7f51535c3a35e2",
                                      "6617178e941f020d351e2f254e8fd32c"
                                      "602420feb0b8fb9adccebb82461e99c5"
                                      "a678cc31e799176d3860e6110c46523e",
                                      "e37b6a775dc87dbaa4dfa9f96e5e3ffd"
                                      "debd71f8867289865df5a32d20cdc944"
                                      "b6022cac3c4982b10d5eeb55c3e4de15"
                                      "134676fb6de0446065c97440fa8c6a58"}}};

    return testData;
}

class HmacTests : public testing::TestWithParam<inputData>
{
};
INSTANTIATE_TEST_SUITE_P(hmac, HmacTests, testing::ValuesIn(prepareTestDataForHmacTests()));

TEST_P(HmacTests, tests) { testHmac(GetParam()); }

class HmacTests2 : public testing::Test
{
protected:
    mococrw::HMAC getHmac()
    {
        testData = prepareTestDataForHmacTests().at(0);
        auto hmac = mococrw::HMAC(openssl::DigestTypes::SHA512, utility::fromHex(testData.key));
        return hmac;
    }

    inputData testData;
};

TEST_F(HmacTests2, checkInvocationOrder)
{
    auto hmac = getHmac();
    hmac.update(utility::fromHex(testData.data));
    hmac.verify(utility::fromHex(testData.expectedResultSha512));

    /* verify implicitly invokes finish, if finish wasn't invoked before */
    EXPECT_THROW(hmac.finish(), MoCOCrWException);

    /* update is not allowed after finish or verify */
    EXPECT_THROW(hmac.update(utility::fromHex(testData.data)), MoCOCrWException);

    /* verify can be invoked multiple times */
    hmac.verify(utility::fromHex(testData.expectedResultSha512));
}

TEST_F(HmacTests2, checkVerify)
{
    /* Calculate the MAC */
    auto hmac = getHmac();
    hmac.update(utility::fromHex(testData.data));
    hmac.finish();
    std::vector<uint8_t> expected = utility::fromHex(testData.expectedResultSha512);

    /* standard verify */
    hmac.verify(expected);

    /* Check a value longer than the calculated value */
    expected.push_back(5);
    EXPECT_THROW(hmac.verify(expected), MoCOCrWException);

    /* Check a value shorter than the calculated value */
    expected.resize(expected.size() - 2);
    EXPECT_THROW(hmac.verify(expected), MoCOCrWException);

    /* Check an invalid value */
    expected[0] += 1;
    EXPECT_THROW(hmac.verify(expected), MoCOCrWException);
}

TEST(HmacTests3, checkConstructor)
{
    /* Check for failure on empty key */
    EXPECT_THROW(mococrw::HMAC(openssl::DigestTypes::SHA512, std::vector<uint8_t>()),
                 MoCOCrWException);
}
