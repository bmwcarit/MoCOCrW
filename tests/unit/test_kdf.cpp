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

#include "mococrw/hash.h"
#include "mococrw/kdf.h"

using namespace mococrw;

using testing::Eq;

struct inputData
{
    openssl::DigestTypes hashFunction;
    std::vector<uint8_t> password;
    std::vector<uint8_t> salt;
    uint iterations;
    uint olen;
    std::string expectedRestult;
};

void testPbkfd2(struct inputData data)
{
    auto pbkfd2 = PBKDF2(data.hashFunction, data.iterations);
    ASSERT_THAT(utility::toHex(pbkfd2.deriveKey(data.password, data.olen, data.salt)),
                Eq(data.expectedRestult));
}

static std::vector<inputData> prepareTestDataForPbkdf2Tests()
{
    std::vector<inputData> testData{{openssl::DigestTypes::SHA1,
                                     {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'},
                                     {'s', 'a', 'l', 't'},
                                     1,
                                     20,
                                     "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
                                    {openssl::DigestTypes::SHA1,
                                     {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'},
                                     {'s', 'a', 'l', 't'},
                                     2,
                                     20,
                                     "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
                                    {openssl::DigestTypes::SHA1,
                                     {'p', 'a', 's', 's', '\0', 'w', 'o', 'r', 'd'},
                                     {'s', 'a', '\0', 'l', 't'},
                                     4096,
                                     16,
                                     "56fa6aa75548099dcc37d7f03425e0c3"},
                                    {openssl::DigestTypes::SHA512,
                                     {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'},
                                     {'s', 'a', 'l', 't'},
                                     1,
                                     64,
                                     "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf"
                                     "252c02d470a285a0501bad999bfe943c08f050235d7d68b"
                                     "1da55e63f73b60a57fce"},
                                    {openssl::DigestTypes::SHA512,
                                     {'p', 'a', 's', 's', 'w', 'o', 'r', 'd'},
                                     {'s', 'a', 'l', 't'},
                                     4096,
                                     64,
                                     "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f45"
                                     "7b5143f30602641b3d55cd335988cb36b84376060ecd532"
                                     "e039b742a239434af2d5"}

    };
    return testData;
}

class Pbkdf2Tests : public testing::TestWithParam<inputData>
{
};
INSTANTIATE_TEST_SUITE_P(pbkdf2, Pbkdf2Tests, testing::ValuesIn(prepareTestDataForPbkdf2Tests()));

TEST_P(Pbkdf2Tests, tests) { testPbkfd2(GetParam()); }

void testX963kdf(struct inputData data)
{
    auto x963kdf = X963KDF(data.hashFunction);
    ASSERT_THAT(utility::toHex(x963kdf.deriveKey(data.password, data.olen, data.salt)),
                Eq(data.expectedRestult));
}

static std::vector<inputData> prepareTestDataForX963Tests()
{
    /* All Test data is taken from
     * https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Component-Testing
     */
    std::vector<inputData> testData{
            {openssl::DigestTypes::SHA1,
             utility::fromHex("1c7d7b5f0597b03d06a018466ed1a93e30ed4b04dc64ccdd"),
             utility::fromHex(""),
             0,
             128 / 8,
             "bf71dffd8f4d99223936beb46fee8ccc"},
            {openssl::DigestTypes::SHA256,
             utility::fromHex("96c05619d56c328ab95fe84b18264b08725b85e33fd34f08"),
             utility::fromHex(""),
             0,
             128 / 8,
             "443024c3dae66b95e6f5670601558f71"},
            {openssl::DigestTypes::SHA256,
             utility::fromHex("22518b10e70f2a3f243810ae3254139efbee04aa57c7af7d"),
             utility::fromHex("75eef81aa3041e33b80971203d2c0c52"),
             0,
             1024 / 8,
             "c498af77161cc59f2962b9a713e2b215152d139766ce34a776df11866a69bf2e52a13d9c7c6fc878c50c5"
             "ea0bc7b00e0da2447cfd8"
             "74f6cf92f30d0097111485500c90c3af8b487872d04685d14c8d1dc8d7fa08beb0ce0ababc11f0bd49626"
             "9142d43525a78e5bc79a1"
             "7f59676a5706dc54d54d4d1f0bd7e386128ec26afc21"},
            {openssl::DigestTypes::SHA384,
             utility::fromHex("d8554db1b392cd55c3fe957bed76af09c13ac2a9392f88f6"),
             utility::fromHex(""),
             0,
             128 / 8,
             "671a46aada145162f8ddf1ca586a1cda"},
            {openssl::DigestTypes::SHA384,
             utility::fromHex("c051fd22539c9de791d6c43a854b8f80a6bf70190050854a"),
             utility::fromHex("1317504aa34759bb4c931e3b78201945"),
             0,
             1024 / 8,
             "cf6a84434734ac6949e1d7976743277be789906908ad3ca3a8923da7f476abbeb574306d7243031a85566"
             "914bfd247d2519c479953d"
             "9d55b6b831e56260806c39af21b74e3ecf470e3bd8332791c8a23c13352514fdef00c2d1a408ba31b2d3f"
             "9fdcb373895484649a645d"
             "1845eec91b5bfdc5ad28c7824984482002dd4a8677"},
            {openssl::DigestTypes::SHA512,
             utility::fromHex("87fc0d8c4477485bb574f5fcea264b30885dc8d90ad82782"),
             utility::fromHex(""),
             0,
             128 / 8,
             "947665fbb9152153ef460238506a0245"},
            {openssl::DigestTypes::SHA512,
             utility::fromHex("00aa5bb79b33e389fa58ceadc047197f14e73712f452caa9fc4c9adb369348b81507"
                              "392f1a86ddfdb7c4ff8231"
                              "c4bd0f44e44a1b55b1404747a9e2e753f55ef05a2d"),
             utility::fromHex("e3b5b4c1b0d5cf1d2b3a2f9937895d31"),
             0,
             1024 / 8,
             "4463f869f3cc18769b52264b0112b5858f7ad32a5a2d96d8cffabf7fa733633d6e4dd2a599acceb3ea54a"
             "6217ce0b50eef4f6b40a5c"
             "30250a5a8eeee208002267089dbf351f3f5022aa9638bf1ee419dea9c4ff745a25ac27bda33ca08bd56dd"
             "1a59b4106cf2dbbc0ab2aa"
             "8e2efa7b17902d34276951ceccab87f9661c3e8816"}};
    return testData;
}

class X963Tests : public testing::TestWithParam<inputData>
{
};
INSTANTIATE_TEST_SUITE_P(x9_63, X963Tests, testing::ValuesIn(prepareTestDataForX963Tests()));

TEST_P(X963Tests, tests) { testX963kdf(GetParam()); }
