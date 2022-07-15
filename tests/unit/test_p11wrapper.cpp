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

#include <boost/core/null_deleter.hpp>

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

    // Helper functions to avoid code duplication:
    void testGoodOpenSessionHelper(int rawMode, SessionMode mode);
    P11_SlotInfo testCreateSlotInfoHelper(PKCS11_CTX *context,
                                          PKCS11_SLOT *slotsp,
                                          unsigned int nslotsp,
                                          int retVal);
    void testFindSlotHelper(PKCS11_CTX *context, PKCS11_SLOT *slot, PKCS11_SLOT *retSlot);
    void testIsLoginHelper(PKCS11_SLOT *rawSlot, int isLoggedIn, int retVal);
    P11_Session testCreateSessionHelper(PKCS11_SLOT *someSlot,
                                        std::string &pin,
                                        SessionMode mode,
                                        int loginRetVal);
    void testPrivStoreHelper(SessionMode mode, int retVal);
    void testPubStoreHelper(SessionMode mode, int retVal);
    void testKeyGenHelper(SessionMode mode, int retVal);
};

namespace testutils
{
// The following some* functions return dummy pointers, which are never dereferenced and
// are just required to get several tests going:

PKCS11_CTX *somePKCS11CtxPtr()
{
    /* Reserve some memory and cast a pointer to that ; the pointer will not be dereferenced */
    static char dummyBuf[42] = {};
    return reinterpret_cast<PKCS11_CTX *>(&dummyBuf);
}

PKCS11_TOKEN *somePKCS11TokenPtr()
{
    /* Reserve some memory and cast a pointer to that ; the pointers will not be dereferenced */
    static char dummyBuf[42] = {};
    return reinterpret_cast<PKCS11_TOKEN *>(&dummyBuf);
}

PKCS11_SLOT *somePKCS11SlotPtr()
{
    /* Reserve some memory and cast a pointer to that */
    static PKCS11_SLOT slot = {};
    slot.token = somePKCS11TokenPtr();
    return reinterpret_cast<PKCS11_SLOT *>(&slot);
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
TEST_F(P11WrapperTest, badCreatePKCS11Ctx)
{
    std::string mod = "test_mod";

    EXPECT_CALL(_mock(), P11_PKCS11_CTX_new()).WillOnce(Return(nullptr));
    EXPECT_THROW(_PKCS11_CTX_create(mod), P11Exception);
}

/* Test that exception is triggered if P11_PKCS11_CTX_load()
 * fails.
 */
TEST_F(P11WrapperTest, badCreatePKCS11Ctx2)
{
    std::string mod = "test_mod";

    EXPECT_CALL(_mock(), P11_PKCS11_CTX_new()).WillOnce(Return(::testutils::somePKCS11CtxPtr()));
    EXPECT_CALL(_mock(), P11_PKCS11_CTX_load(::testutils::somePKCS11CtxPtr(), mod.c_str()))
            .WillOnce(Return(-1));
    // Should be called to free the allocated ctx.
    EXPECT_CALL(_mock(), P11_PKCS11_CTX_free(::testutils::somePKCS11CtxPtr()));

    EXPECT_THROW(_PKCS11_CTX_create(mod), P11Exception);
}

/* Test successful _PKCS11_CTX_create(). */
TEST_F(P11WrapperTest, goodCreatePKCS11Ctx)
{
    std::string mod = "test_mod";

    EXPECT_CALL(_mock(), P11_PKCS11_CTX_new()).WillOnce(Return(::testutils::somePKCS11CtxPtr()));
    EXPECT_CALL(_mock(), P11_PKCS11_CTX_load(::testutils::somePKCS11CtxPtr(), mod.c_str()))
            .WillOnce(Return(0));

    /* Since we wrap in a unique_ptr, expect a call to the "free" function */
    EXPECT_CALL(_mock(), P11_PKCS11_CTX_unload(::testutils::somePKCS11CtxPtr()));
    EXPECT_CALL(_mock(), P11_PKCS11_CTX_free(::testutils::somePKCS11CtxPtr()));

    EXPECT_NO_THROW(_PKCS11_CTX_create(mod));
}

P11_SlotInfo P11WrapperTest::testCreateSlotInfoHelper(PKCS11_CTX *context,
                                                      PKCS11_SLOT *slotsp,
                                                      unsigned int nslotsp,
                                                      int retVal)
{
    auto ctx = P11_PKCS11_CTX_Ptr(context, boost::null_deleter());

    EXPECT_CALL(_mock(), P11_PKCS11_enumerate_slots(context, _, _))
            .WillOnce(DoAll(SetArgPointee<1>(slotsp), SetArgPointee<2>(nslotsp), Return(retVal)));

    if (retVal == 0 && slotsp != nullptr) {
        // If enumeration is successful, then we expect there to be a release upon slot list
        // destruction.
        EXPECT_CALL(_mock(), P11_PKCS11_release_all_slots(context, slotsp, nslotsp))
                .WillOnce(Return());
    }

    return P11_SlotInfo(ctx);
}

/* Test bad creation of SlotInfo due to returned error value. */
TEST_F(P11WrapperTest, badSlotInfoCreation)
{
    EXPECT_THROW(P11WrapperTest::testCreateSlotInfoHelper(
                         ::testutils::somePKCS11CtxPtr(), ::testutils::somePKCS11SlotPtr(), 1, -1),
                 P11Exception);
}

/* Test bad creation of SlotInfo due to NULL slot list. */
TEST_F(P11WrapperTest, badSlotInfoCreation2)
{
    EXPECT_THROW(
            {
                try {
                    testCreateSlotInfoHelper(::testutils::somePKCS11CtxPtr(), nullptr, 1, 0);
                } catch (const P11Exception &e) {
                    EXPECT_STREQ(P11Exception::nullSlotListExceptionString.c_str(), e.what());
                    throw;
                }
            },
            P11Exception);
}

/* Test successful creation of SlotInfo */
TEST_F(P11WrapperTest, goodSlotInfoCreation)
{
    EXPECT_NO_THROW(P11WrapperTest::testCreateSlotInfoHelper(
            ::testutils::somePKCS11CtxPtr(), ::testutils::somePKCS11SlotPtr(), 1, 0));
}

void P11WrapperTest::testFindSlotHelper(PKCS11_CTX *context,
                                        PKCS11_SLOT *slot,
                                        PKCS11_SLOT *retSlot)
{
    auto slotInfo = P11WrapperTest::testCreateSlotInfoHelper(context, slot, 1, 0);

    EXPECT_CALL(_mock(),
                P11_PKCS11_find_token(
                        ::testutils::somePKCS11CtxPtr(), ::testutils::somePKCS11SlotPtr(), 1))
            .WillOnce(Return(retSlot));

    slotInfo.findSlot();
}

/* Test P11_PKCS11_find_token() with bad return value. */
TEST_F(P11WrapperTest, badSlotFinding)
{
    EXPECT_THROW(
            testFindSlotHelper(
                    ::testutils::somePKCS11CtxPtr(), ::testutils::somePKCS11SlotPtr(), nullptr),
            P11Exception);
}

/* Test successful P11_PKCS11_find_token(). */
TEST_F(P11WrapperTest, goodSlotFinding)
{
    EXPECT_NO_THROW(testFindSlotHelper(::testutils::somePKCS11CtxPtr(),
                                       ::testutils::somePKCS11SlotPtr(),
                                       ::testutils::somePKCS11SlotPtr()));
}

/* Test bad session creation due to P11_PKCS11_open_session() returning an error value. */
TEST_F(P11WrapperTest, badOpenSession)
{
    auto slot = P11_PKCS11_SLOT_PTR(::testutils::somePKCS11SlotPtr(), boost::null_deleter());
    std::string pin = "1002";
    SessionMode mode = ReadWrite;

    EXPECT_CALL(_mock(), P11_PKCS11_open_session(::testutils::somePKCS11SlotPtr(), mode))
            .WillOnce(Return(-1));

    EXPECT_THROW(P11_Session(slot, pin, mode), P11Exception);
}

void P11WrapperTest::testIsLoginHelper(PKCS11_SLOT *rawSlot, int isLoggedIn, int retVal)
{
    auto slot = P11_PKCS11_SLOT_PTR(rawSlot, boost::null_deleter());
    std::string pin = "1002";
    SessionMode mode = ReadWrite;

    EXPECT_CALL(_mock(), P11_PKCS11_open_session(rawSlot, mode)).WillOnce(Return(0));

    EXPECT_CALL(_mock(), P11_PKCS11_is_logged_in(rawSlot, 0, _))
            .WillOnce(DoAll(SetArgPointee<2>(isLoggedIn), Return(retVal)));

    P11_Session(slot, pin, mode);
}

/* Test bad session creation due to P11_PKCS11_is_logged_in() returning an error value. */
TEST_F(P11WrapperTest, badIsLogin)
{
    EXPECT_THROW(testIsLoginHelper(::testutils::somePKCS11SlotPtr(), 0 /* not logged in */, -1),
                 P11Exception);
}

/* Test bad session creation due to login mismatch. */
TEST_F(P11WrapperTest, badIsLogin2)
{
    EXPECT_THROW(
            {
                try {
                    testIsLoginHelper(::testutils::somePKCS11SlotPtr(), 1 /* is logged in */, 0);
                } catch (const P11Exception &e) {
                    EXPECT_STREQ(P11Exception::mismatchLoginExceptionString.c_str(), e.what());
                    throw;
                }
            },
            P11Exception);
}

P11_Session P11WrapperTest::testCreateSessionHelper(PKCS11_SLOT *someSlot,
                                                    std::string &pin,
                                                    SessionMode mode,
                                                    int loginRetVal)
{
    auto slot = P11_PKCS11_SLOT_PTR(someSlot, boost::null_deleter());

    EXPECT_CALL(_mock(), P11_PKCS11_open_session(someSlot, mode)).WillOnce(Return(0));

    EXPECT_CALL(_mock(), P11_PKCS11_is_logged_in(someSlot, 0 /* Not SO */, _))
            .WillOnce(DoAll(SetArgPointee<2>(0), Return(0)))
            .WillRepeatedly(DoAll(SetArgPointee<2>(1), Return(0)));

    EXPECT_CALL(_mock(), P11_PKCS11_login(someSlot, 0 /* Not SO */, pin.c_str()))
            .WillOnce(Return(loginRetVal));

    if (loginRetVal == 0) {
        // If login successful, we expect a logout upon session destruction.
        EXPECT_CALL(_mock(), P11_PKCS11_logout(someSlot)).WillOnce(Return(0));
    }

    return P11_Session(slot, pin, mode);
}

/* Test bad session creation due to P11_PKCS11_login() returning an error value. */
TEST_F(P11WrapperTest, badLogin)
{
    std::string pin = "1002";
    SessionMode mode = ReadWrite;

    EXPECT_THROW(testCreateSessionHelper(::testutils::somePKCS11SlotPtr(), pin, mode, -1),
                 P11Exception);
}

/* Test successful session creation with read/write mode. */
TEST_F(P11WrapperTest, goodCreateSession)
{
    std::string pin = "1002";
    SessionMode mode = ReadWrite;

    EXPECT_NO_THROW(testCreateSessionHelper(::testutils::somePKCS11SlotPtr(), pin, mode, 0));
}

/* Test successful session creation without write permissions. */
TEST_F(P11WrapperTest, goodCreatreSession2)
{
    std::string pin = "1002";
    SessionMode mode = ReadOnly;

    EXPECT_NO_THROW(testCreateSessionHelper(::testutils::somePKCS11SlotPtr(), pin, mode, 0));
}

void P11WrapperTest::testPrivStoreHelper(SessionMode mode, int retVal)
{
    std::string pin = "1002";
    P11_Session session = testCreateSessionHelper(::testutils::somePKCS11SlotPtr(), pin, mode, 0);

    EXPECT_CALL(_mock(),
                P11_PKCS11_store_private_key(
                        ::testutils::somePKCS11TokenPtr(), ::testutils::someEVP_PKEY(), _, _, _))
            .WillOnce(Return(retVal));

    _PKCS11_store_private_key(session, ::testutils::someEVP_PKEY(), "label", "1001");
}

/* Test _PKCS11_store_private_key() with error return value. */
TEST_F(P11WrapperTest, badPrivStore)
{
    SessionMode mode = ReadWrite;

    EXPECT_THROW(testPrivStoreHelper(mode, -1), P11Exception);
}

/* Test successful _PKCS11_store_private_key(). */
TEST_F(P11WrapperTest, goodPrivStore)
{
    SessionMode mode = ReadWrite;

    EXPECT_NO_THROW(testPrivStoreHelper(mode, 0));
}

void P11WrapperTest::testPubStoreHelper(SessionMode mode, int retVal)
{
    std::string pin = "1002";
    P11_Session session = testCreateSessionHelper(::testutils::somePKCS11SlotPtr(), pin, mode, 0);

    EXPECT_CALL(_mock(),
                P11_PKCS11_store_public_key(
                        ::testutils::somePKCS11TokenPtr(), ::testutils::someEVP_PKEY(), _, _, _))
            .WillOnce(Return(retVal));

    _PKCS11_store_public_key(session, ::testutils::someEVP_PKEY(), "label", "1001");
}

/* Test bad public storage. */
TEST_F(P11WrapperTest, badPubStore)
{
    SessionMode mode = ReadWrite;

    EXPECT_THROW(testPubStoreHelper(mode, -1), P11Exception);
}

/* Test successful public storage. */
TEST_F(P11WrapperTest, goodPubStore)
{
    SessionMode mode = ReadWrite;

    EXPECT_NO_THROW(testPubStoreHelper(mode, 0));
}

void P11WrapperTest::testKeyGenHelper(SessionMode mode, int retVal)
{
    std::string pin = "1002";
    P11_Session session = testCreateSessionHelper(::testutils::somePKCS11SlotPtr(), pin, mode, 0);

    EXPECT_CALL(_mock(),
                P11_PKCS11_generate_key(::testutils::somePKCS11TokenPtr(), _, 2048, _, _, _))
            .WillOnce(Return(retVal));

    _PKCS11_generate_key(session, 2048, "label", "1001");
}

/* Test _PKCS11_generate_key() with error return value. */
TEST_F(P11WrapperTest, badKeyGen)
{
    SessionMode mode = ReadWrite;

    EXPECT_THROW(testKeyGenHelper(mode, -1);, P11Exception);
}

/* Test successful _PKCS11_generate_key(). */
TEST_F(P11WrapperTest, goodKeyGen)
{
    SessionMode mode = ReadWrite;

    EXPECT_NO_THROW(testKeyGenHelper(mode, 0));
}
