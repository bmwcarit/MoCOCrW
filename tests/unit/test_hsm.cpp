/*
 * #%L
 * %%
 * Copyright (C) 2022 BMW Car IT GmbH
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

#include <cstring>
#include <string>

#include "mococrw/hsm.h"
#include "mococrw/key.h"
#include "openssl_lib_mock.h"

using namespace ::mococrw;
using namespace ::std::string_literals;

using ::testing::_;
using ::testing::Mock;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::Throw;

class HSMTest : public ::testing::Test
{
public:
    void SetUp() override;
    void TearDown() override;

protected:
    std::string _defaultErrorMessage{"bla bla err msg"};
    std::string _defaultErrorLibrary{"bla bla err lib"};
    std::string _defaultErrorReason{"bla bla err reason"};
    const unsigned long _defaultErrorCode = 1L;
    openssl::OpenSSLLibMock &_mock() const
    {
        return openssl::OpenSSLLibMockManager::getMockInterface();
    }

    std::string pin = "1234";
    std::unique_ptr<HsmEngine> initialiseEngine();
};

namespace testutils
{
EVP_PKEY *somePkeyPtr()
{
    /* Reserve some memory and cast a pointer to that ; pointers will not be dereferenced */
    static char dummyBuf[42] = {};
    return reinterpret_cast<EVP_PKEY *>(&dummyBuf);
}

ENGINE *someEnginePtr()
{
    /* Reserve some memory and cast a pointer to that ; pointers will not be dereferenced */
    static char dummyBuf[42] = {};
    return reinterpret_cast<ENGINE *>(&dummyBuf);
}
}  // namespace testutils

void HSMTest::SetUp()
{
    /*
     * Like test_opensslwrapper.cpp, we instrument the mock, so that error-handling code
     * will always have well-defined behavior.
     */
    openssl::OpenSSLLibMockManager::resetMock();
    ON_CALL(_mock(), SSL_ERR_get_error()).WillByDefault(Return(_defaultErrorCode));
    ON_CALL(_mock(), SSL_ERR_error_string(_, nullptr))
            .WillByDefault(Return(const_cast<char *>(_defaultErrorMessage.c_str())));
    ON_CALL(_mock(), SSL_ERR_lib_error_string(_))
            .WillByDefault(Return(const_cast<char *>(_defaultErrorLibrary.c_str())));
    ON_CALL(_mock(), SSL_ERR_reason_error_string(_))
            .WillByDefault(Return(const_cast<char *>(_defaultErrorReason.c_str())));
    // TODO: Get rid of the uninteresting calls by default here somehow...
}

void HSMTest::TearDown() { openssl::OpenSSLLibMockManager::destroy(); }

std::unique_ptr<HsmEngine> HSMTest::initialiseEngine()
{
    std::string engineID("engine_id");
    std::string modulePath("/test_path.so");
    std::string tokenLabel("token-label");
    auto engine = ::testutils::someEnginePtr();

    EXPECT_CALL(_mock(), SSL_ENGINE_by_id(StrEq(engineID.c_str()))).WillOnce(Return(engine));

    EXPECT_CALL(
            _mock(),
            SSL_ENGINE_ctrl_cmd_string(
                    engine, StrEq("MODULE_PATH"), StrEq(modulePath.c_str()), 0 /*non-optional*/))
            .WillOnce(Return(1));

    EXPECT_CALL(_mock(), SSL_ENGINE_init(engine)).WillOnce(Return(1));
    EXPECT_CALL(_mock(), SSL_ENGINE_finish(engine)).WillOnce(Return(1));

    return std::make_unique<HsmEngine>(engineID, modulePath, tokenLabel, pin);
}

TEST_F(HSMTest, testHSMKeygen)
{
    ECCSpec eccSpec;
    int curve = int(mococrw::openssl::ellipticCurveNid::PRIME_256v1);
    auto engine = ::testutils::someEnginePtr();
    auto pkey = ::testutils::somePkeyPtr();
    auto hsm = initialiseEngine();
    std::string keyLabel{"key-label"};
    std::vector<uint8_t> keyId{0x12};
    EXPECT_CALL(_mock(),
                SSL_ENGINE_ctrl_cmd_string(
                        engine, StrEq("PIN"), StrEq(pin.c_str()), 0 /*non-optional*/))
            .WillOnce(Return(1))
            .WillOnce(Return(1))
            .WillOnce(Return(1));
    EXPECT_CALL(_mock(),
                SSL_ENGINE_load_private_key(
                        engine, StrEq("pkcs11:token=token-label;id=%12"), nullptr, nullptr))
            .WillOnce(Return(nullptr))
            .WillOnce(Return(pkey));
    ON_CALL(_mock(), SSL_ERR_lib_error_string(_)).WillByDefault(Return("pkcs11 engine"));
    ON_CALL(_mock(), SSL_ERR_reason_error_string(_)).WillByDefault(Return("object not found"));
    EXPECT_CALL(_mock(), SSL_EC_curve_nid2nist(curve)).WillOnce(Return("P-256"));
    EXPECT_CALL(_mock(),
                SSL_ENGINE_ctrl_cmd(engine, StrEq("KEYGEN"), 0 /*non-optional*/, _, nullptr, 1))
            .WillOnce(Return(1));
    EXPECT_NO_THROW(AsymmetricKeypair::generateKeyOnHSM(*hsm, eccSpec, keyLabel, keyId));
}

TEST_F(HSMTest, testHSMTryLoadKeyWithEmptyId)
{
    auto hsm = initialiseEngine();
    const std::string keyLabel{"key-label"};
    const std::vector<uint8_t> keyId{};

    EXPECT_THROW(AsymmetricPublicKey::readPublicKeyFromHSM(*hsm, keyLabel, keyId),
                 MoCOCrWException);
}

TEST_F(HSMTest, testHSMLoadUnknownPublicKey)
{
    auto engine = ::testutils::someEnginePtr();
    auto hsm = initialiseEngine();
    const std::string keyLabel{"key-label"};
    const std::vector<uint8_t> keyId{0x12};
    EXPECT_CALL(_mock(),
                SSL_ENGINE_ctrl_cmd_string(
                        engine, StrEq("PIN"), StrEq(pin.c_str()), 0 /*non-optional*/))
            .WillOnce(Return(1));
    EXPECT_CALL(
            _mock(),
            SSL_ENGINE_load_public_key(engine,
                                       StrEq("pkcs11:token=token-label;id=%12;object=key-label"),
                                       nullptr,
                                       nullptr))
            .WillOnce(Return(nullptr));

    ON_CALL(_mock(), SSL_ERR_lib_error_string(_)).WillByDefault(Return("pkcs11 engine"));
    ON_CALL(_mock(), SSL_ERR_reason_error_string(_)).WillByDefault(Return("object not found"));

    EXPECT_THROW(AsymmetricPublicKey::readPublicKeyFromHSM(*hsm, keyLabel, keyId),
                 MoCOCrWException);
}

TEST_F(HSMTest, testHSMLoadUnknownPrivateKey)
{
    auto engine = ::testutils::someEnginePtr();
    auto hsm = initialiseEngine();
    const std::string keyLabel{"key-label"};
    const std::vector<uint8_t> keyId{0x12};
    EXPECT_CALL(_mock(),
                SSL_ENGINE_ctrl_cmd_string(
                        engine, StrEq("PIN"), StrEq(pin.c_str()), 0 /*non-optional*/))
            .WillOnce(Return(1));
    EXPECT_CALL(
            _mock(),
            SSL_ENGINE_load_private_key(engine,
                                        StrEq("pkcs11:token=token-label;id=%12;object=key-label"),
                                        nullptr,
                                        nullptr))
            .WillOnce(Return(nullptr));

    ON_CALL(_mock(), SSL_ERR_lib_error_string(_)).WillByDefault(Return("pkcs11 engine"));
    ON_CALL(_mock(), SSL_ERR_reason_error_string(_)).WillByDefault(Return("object not found"));

    EXPECT_THROW(AsymmetricKeypair::readPrivateKeyFromHSM(*hsm, keyLabel, keyId), MoCOCrWException);
}
