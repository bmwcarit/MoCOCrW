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

#include "mococrw/p11_wrap.h"
#include "p11_lib_mock.h"

using namespace ::mococrw::p11;
using namespace ::std::string_literals;

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::DoAll;
using ::testing::Mock;
using ::testing::Return;
using ::testing::SetArgPointee;

/**
 * Test the P11 wrapper.
 *
 * These tests are to determine that the p11-wrapper,
 * declared and defined in p11_wrap.h and p11_wrap.cpp
 * behaves as intended and calls the underlying p11 library
 * correctly.
 *
 */
class P11WrapperTest : public ::testing::Test
{
public:
    void SetUp() override;
    void TearDown() override;

protected:
    LibP11Mock &_mock() const { return LibP11MockManager::getMockInterface(); }
};

namespace testutils
{
PKCS11_CTX *somePKCS11CtxPtr()
{
    /* Reserve some memory and cast a pointer to that ; pointers will not be dereferenced */
    static char dummyBuf[42] = {};
    return reinterpret_cast<PKCS11_CTX *>(&dummyBuf);
}

PKCS11_SLOT *somePKCS11SlotPtr()
{
    /* Reserve some memory and cast a pointer to that ; pointers will not be dereferenced */
    static char dummyBuf[42] = {};
    return reinterpret_cast<PKCS11_SLOT *>(&dummyBuf);
}

PKCS11_TOKEN *somePKCS11TokenPtr()
{
    /* Reserve some memory and cast a pointer to that ; pointers will not be dereferenced */
    static char dummyBuf[42] = {};
    return reinterpret_cast<PKCS11_TOKEN *>(&dummyBuf);
}

EVP_PKEY *someEVP_PKEY()
{
    /* Reserve some memory and cast a pointer to that ; pointers will not be dereferenced */
    static char dummyBuf[42] = {};
    return reinterpret_cast<EVP_PKEY *>(&dummyBuf);
}

}  // namespace testutils

void P11WrapperTest::SetUp() { LibP11MockManager::resetMock(); }

void P11WrapperTest::TearDown() { LibP11MockManager::destroy(); }

/* Test that exception is triggered if P11_PKCS11_CTX_new()
 * returns NULL.
 */
TEST_F(P11WrapperTest, badInitPKCS11Ctx)
{
    EXPECT_CALL(_mock(), P11_PKCS11_CTX_new()).WillOnce(Return(nullptr));

    EXPECT_THROW(_PKCS11_CTX_new(), P11Exception);
}

/* Test successful _PKCS11_CTX_new(). */
TEST_F(P11WrapperTest, goodInitPKCS11Ctx)
{
    EXPECT_CALL(_mock(), P11_PKCS11_CTX_new()).WillOnce(Return(::testutils::somePKCS11CtxPtr()));

    /* Since we wrap in a unique_ptr, expect a call to the "free" function */
    EXPECT_CALL(_mock(), P11_PKCS11_CTX_free(::testutils::somePKCS11CtxPtr()));

    EXPECT_NO_THROW(_PKCS11_CTX_new());
}

/* Test failed _PKCS11_CTX_load(). */
TEST_F(P11WrapperTest, badPKCS11Load)
{
    std::string test = "test";

    EXPECT_CALL(_mock(), P11_PKCS11_CTX_load(nullptr, test.c_str())).WillOnce(Return(-1));

    EXPECT_THROW(_PKCS11_CTX_load(nullptr, test), P11Exception);
}

/* Test successful _PKCS11_CTX_load(). */
TEST_F(P11WrapperTest, goodPKCS11Load)
{
    std::string test = "test";
    EXPECT_CALL(_mock(), P11_PKCS11_CTX_load(::testutils::somePKCS11CtxPtr(), test.c_str()))
            .WillOnce(Return(0));

    EXPECT_NO_THROW(_PKCS11_CTX_load(::testutils::somePKCS11CtxPtr(), test));
}

/* Test  _PKCS11_enumerate_slots() with NULL context. */
TEST_F(P11WrapperTest, badSlotEnumeration)
{
    EXPECT_THROW(_PKCS11_enumerate_slots(nullptr), P11Exception);
}

/* Test _PKCS11_enumerate_slots with valid context. */
TEST_F(P11WrapperTest, goodSlotEnumeration)
{
    EXPECT_CALL(_mock(), P11_PKCS11_enumerate_slots(::testutils::somePKCS11CtxPtr(), _, _))
            .WillOnce(Return(0));

    EXPECT_NO_THROW(_PKCS11_enumerate_slots(::testutils::somePKCS11CtxPtr()));
}

/* Test _PKCS11_release_all_slots() with NULL context. */
TEST_F(P11WrapperTest, badSlotRelease)
{
    P11_SlotInfo slotInfo(::testutils::somePKCS11SlotPtr(), 2);
    EXPECT_THROW(_PKCS11_release_all_slots(nullptr, slotInfo), P11Exception);
}

/* Test _PKCS11_release_all_slots() with bad slot information. */
TEST_F(P11WrapperTest, badSlotRelease2)
{
    P11_SlotInfo slotInfo;
    EXPECT_THROW(_PKCS11_release_all_slots(::testutils::somePKCS11CtxPtr(), slotInfo),
                 P11Exception);
}

/* Test successful _PKCS11_release_all_slots().
 */
TEST_F(P11WrapperTest, goodSlotRelease)
{
    P11_SlotInfo slotInfo(::testutils::somePKCS11SlotPtr(), 2);

    EXPECT_CALL(_mock(),
                P11_PKCS11_release_all_slots(
                        ::testutils::somePKCS11CtxPtr(), slotInfo._slots, slotInfo._numSlots))
            .WillOnce(Return());

    EXPECT_NO_THROW(_PKCS11_release_all_slots(::testutils::somePKCS11CtxPtr(), slotInfo));
}

/* Test _PKCS11_find_token() with NULL PKCS11 context. */
TEST_F(P11WrapperTest, badSlotFinding)
{
    P11_SlotInfo slotInfo(::testutils::somePKCS11SlotPtr(), 2);
    EXPECT_THROW(_PKCS11_find_token(nullptr, slotInfo), P11Exception);
}

/* Test P11_PKCS11_find_token() with bad value. */
TEST_F(P11WrapperTest, badSlotFinding2)
{
    P11_SlotInfo slotInfo(::testutils::somePKCS11SlotPtr(), 2);

    EXPECT_CALL(_mock(),
                P11_PKCS11_find_token(
                        ::testutils::somePKCS11CtxPtr(), slotInfo._slots, slotInfo._numSlots))
            .WillOnce(Return(nullptr));

    EXPECT_THROW(_PKCS11_find_token(::testutils::somePKCS11CtxPtr(), slotInfo), P11Exception);
}

/* Test successful P11_PKCS11_find_token(). */
TEST_F(P11WrapperTest, goodSlotFinding)
{
    P11_SlotInfo slotInfo(::testutils::somePKCS11SlotPtr(), 2);

    EXPECT_CALL(_mock(),
                P11_PKCS11_find_token(
                        ::testutils::somePKCS11CtxPtr(), slotInfo._slots, slotInfo._numSlots))
            .WillOnce(Return(::testutils::somePKCS11SlotPtr()));

    EXPECT_NO_THROW(_PKCS11_find_token(::testutils::somePKCS11CtxPtr(), slotInfo));
}

/* Test _PKCS11_open_session() with NULL slot pointer. */
TEST_F(P11WrapperTest, badOpenSession)
{
    EXPECT_THROW(_PKCS11_open_session(nullptr, SessionMode::ReadWrite), P11Exception);
}

/* Test _PKCS11_open_session() with error return value. */
TEST_F(P11WrapperTest, badOpenSession2)
{
    EXPECT_CALL(_mock(), P11_PKCS11_open_session(::testutils::somePKCS11SlotPtr(), 1))
            .WillOnce(Return(-1));

    EXPECT_THROW(_PKCS11_open_session(::testutils::somePKCS11SlotPtr(), SessionMode::ReadWrite),
                 P11Exception);
}

/* Test successful _PKCS11_open_session(). */
TEST_F(P11WrapperTest, goodOpenSession)
{
    EXPECT_CALL(_mock(),
                P11_PKCS11_open_session(::testutils::somePKCS11SlotPtr(), SessionMode::ReadWrite))
            .WillOnce(Return(0));

    EXPECT_NO_THROW(_PKCS11_open_session(::testutils::somePKCS11SlotPtr(), SessionMode::ReadWrite));
}

/* Test successful _PKCS11_open_session() without write permissions. */
TEST_F(P11WrapperTest, goodOpenSession2)
{
    EXPECT_CALL(_mock(),
                P11_PKCS11_open_session(::testutils::somePKCS11SlotPtr(), SessionMode::ReadOnly))
            .WillOnce(Return(0));

    EXPECT_NO_THROW(_PKCS11_open_session(::testutils::somePKCS11SlotPtr(), SessionMode::ReadOnly));
}

/* Test _PKCS11_login() with NULL slot pointer. */
TEST_F(P11WrapperTest, badLogin)
{
    std::string pin = "1002";
    EXPECT_THROW(_PKCS11_login(nullptr, pin), P11Exception);
}

/* Test _PKCS11_login() with error return value. */
TEST_F(P11WrapperTest, badLogin2)
{
    std::string pin = "1002";

    EXPECT_CALL(_mock(), P11_PKCS11_login(::testutils::somePKCS11SlotPtr(), 0, _))
            .WillOnce(Return(-1));

    EXPECT_THROW(_PKCS11_login(::testutils::somePKCS11SlotPtr(), pin), P11Exception);
}

/* Test successful _PKCS11_login(). */
TEST_F(P11WrapperTest, goodLogin)
{
    std::string pin = "1002";

    EXPECT_CALL(_mock(), P11_PKCS11_login(::testutils::somePKCS11SlotPtr(), 0, _))
            .WillOnce(Return(0));

    EXPECT_NO_THROW(_PKCS11_login(::testutils::somePKCS11SlotPtr(), pin));
}

/* Test _PKCS11_login() with NULL slot pointer. */
TEST_F(P11WrapperTest, badLogout) { EXPECT_THROW(_PKCS11_logout(nullptr), P11Exception); }

/* Test _PKCS11_logout() with error return value. */
TEST_F(P11WrapperTest, badLogout2)
{
    EXPECT_CALL(_mock(), P11_PKCS11_logout(::testutils::somePKCS11SlotPtr())).WillOnce(Return(-1));

    EXPECT_CALL(_mock(), P11_PKCS11_is_logged_in(::testutils::somePKCS11SlotPtr(), 0, _))
            .WillOnce(DoAll(SetArgPointee<2>(1), Return(0)));

    EXPECT_THROW(_PKCS11_logout(::testutils::somePKCS11SlotPtr()), P11Exception);
}

/* Test successful _PKCS11_logout(). */
TEST_F(P11WrapperTest, goodLogout)
{
    EXPECT_CALL(_mock(), P11_PKCS11_logout(::testutils::somePKCS11SlotPtr())).WillOnce(Return(0));

    EXPECT_CALL(_mock(), P11_PKCS11_is_logged_in(::testutils::somePKCS11SlotPtr(), 0, _))
            .WillOnce(DoAll(SetArgPointee<2>(1), Return(0)));

    EXPECT_NO_THROW(_PKCS11_logout(::testutils::somePKCS11SlotPtr()));
}

/* Test _PKCS11_is_logged_in() with error return value. */
TEST_F(P11WrapperTest, badIsLogin)
{
    EXPECT_CALL(_mock(), P11_PKCS11_is_logged_in(::testutils::somePKCS11SlotPtr(), 0, _))
            .WillOnce(DoAll(SetArgPointee<2>(1), Return(-1)));

    EXPECT_THROW(_PKCS11_is_logged_in(::testutils::somePKCS11SlotPtr()), P11Exception);
}

/* Test successful _PKCS11_is_logged_in() with true for login. */
TEST_F(P11WrapperTest, goodTrueIsLogin)
{
    EXPECT_CALL(_mock(), P11_PKCS11_is_logged_in(::testutils::somePKCS11SlotPtr(), 0, _))
            .WillRepeatedly(DoAll(SetArgPointee<2>(1), Return(0)));

    EXPECT_NO_THROW(_PKCS11_is_logged_in(::testutils::somePKCS11SlotPtr()));
    EXPECT_TRUE(_PKCS11_is_logged_in(::testutils::somePKCS11SlotPtr()));
}

/* Test successful _PKCS11_is_logged_in() with false for login. */
TEST_F(P11WrapperTest, goodFalseIsLogin)
{
    EXPECT_CALL(_mock(), P11_PKCS11_is_logged_in(::testutils::somePKCS11SlotPtr(), 0, _))
            .WillRepeatedly(DoAll(SetArgPointee<2>(0), Return(0)));

    EXPECT_NO_THROW(_PKCS11_is_logged_in(::testutils::somePKCS11SlotPtr()));
    EXPECT_FALSE(_PKCS11_is_logged_in(::testutils::somePKCS11SlotPtr()));
}

/* Test _PKCS11_store_private_key() with error return value. */
TEST_F(P11WrapperTest, badPrivStore)
{
    EXPECT_CALL(_mock(),
                P11_PKCS11_store_private_key(
                        ::testutils::somePKCS11TokenPtr(), ::testutils::someEVP_PKEY(), _, _, _))
            .WillOnce(Return(-1));

    EXPECT_THROW(_PKCS11_store_private_key(::testutils::somePKCS11TokenPtr(),
                                           ::testutils::someEVP_PKEY(),
                                           "label",
                                           "1001"),
                 P11Exception);
}

/* Test successful _PKCS11_store_private_key(). */
TEST_F(P11WrapperTest, goodPrivStore)
{
    EXPECT_CALL(_mock(),
                P11_PKCS11_store_private_key(
                        ::testutils::somePKCS11TokenPtr(), ::testutils::someEVP_PKEY(), _, _, _))
            .WillOnce(Return(0));

    EXPECT_NO_THROW(_PKCS11_store_private_key(
            ::testutils::somePKCS11TokenPtr(), ::testutils::someEVP_PKEY(), "label", "1001"));
}

/* Test _PKCS11_store_public_key() with error return value. */
TEST_F(P11WrapperTest, badPubStore)
{
    EXPECT_CALL(_mock(),
                P11_PKCS11_store_public_key(
                        ::testutils::somePKCS11TokenPtr(), ::testutils::someEVP_PKEY(), _, _, _))
            .WillOnce(Return(-1));

    EXPECT_THROW(_PKCS11_store_public_key(::testutils::somePKCS11TokenPtr(),
                                          ::testutils::someEVP_PKEY(),
                                          "label",
                                          "1001"),
                 P11Exception);
}

/* Test successful _PKCS11_store_public_key(). */
TEST_F(P11WrapperTest, goodPubStore)
{
    EXPECT_CALL(_mock(),
                P11_PKCS11_store_public_key(
                        ::testutils::somePKCS11TokenPtr(), ::testutils::someEVP_PKEY(), _, _, _))
            .WillOnce(Return(0));

    EXPECT_NO_THROW(_PKCS11_store_public_key(
            ::testutils::somePKCS11TokenPtr(), ::testutils::someEVP_PKEY(), "label", "1001"));
}

/* Test _PKCS11_generate_key() with error return value. */
TEST_F(P11WrapperTest, badKeyGen)
{
    EXPECT_CALL(_mock(),
                P11_PKCS11_generate_key(::testutils::somePKCS11TokenPtr(), _, 2048, _, _, _))
            .WillOnce(Return(-1));

    EXPECT_THROW(_PKCS11_generate_key(::testutils::somePKCS11TokenPtr(), 2048, "label", "1001"),
                 P11Exception);
}

/* Test successful _PKCS11_generate_key(). */
TEST_F(P11WrapperTest, goodKeyGen)
{
    EXPECT_CALL(_mock(),
                P11_PKCS11_generate_key(::testutils::somePKCS11TokenPtr(), _, 2048, _, _, _))
            .WillOnce(Return(0));

    EXPECT_NO_THROW(_PKCS11_generate_key(::testutils::somePKCS11TokenPtr(), 2048, "label", "1001"));
}
