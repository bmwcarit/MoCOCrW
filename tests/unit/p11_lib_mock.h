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
#pragma once

#include <memory>
#include <mutex>

#include "mococrw/p11_lib.h"

namespace mococrw
{
namespace p11
{
/**
 * Gmock interface.
 *
 * Gmock requires a virtual interface.
 */
class LibP11MockInterface
{
public:
    virtual ~LibP11MockInterface() = default;

    /* Initialisation */
    virtual PKCS11_CTX *P11_PKCS11_CTX_new(void) = 0;
    virtual int P11_PKCS11_CTX_load(PKCS11_CTX *ctx, const char *ident) = 0;

    /* Slot and Token Management */
    virtual int P11_PKCS11_enumerate_slots(PKCS11_CTX *ctx,
                                           PKCS11_SLOT **slotsp,
                                           unsigned int *nslotsp) = 0;
    virtual void P11_PKCS11_release_all_slots(PKCS11_CTX *ctx,
                                              PKCS11_SLOT *slots,
                                              unsigned int nslots) = 0;
    virtual PKCS11_SLOT *P11_PKCS11_find_token(PKCS11_CTX *ctx,
                                               PKCS11_SLOT *slots,
                                               unsigned int nslots) = 0;

    /* Session and Login */
    virtual int P11_PKCS11_open_session(PKCS11_SLOT *slot, int rw) = 0;
    virtual int P11_PKCS11_login(PKCS11_SLOT *slot, int so, const char *pin) = 0;
    virtual int P11_PKCS11_logout(PKCS11_SLOT *slot) = 0;
    virtual int P11_PKCS11_is_logged_in(PKCS11_SLOT *slot, int so, int *res) = 0;

    /* Key Management */
    virtual int P11_PKCS11_store_private_key(
            PKCS11_TOKEN *token, EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len) = 0;
    virtual int P11_PKCS11_store_public_key(
            PKCS11_TOKEN *token, EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len) = 0;
    virtual int P11_PKCS11_generate_key(PKCS11_TOKEN *token,
                                        int algorithm,
                                        unsigned int bits,
                                        char *label,
                                        unsigned char *id,
                                        size_t id_len) = 0;

    /* Clean-up Functions */
    virtual void P11_PKCS11_CTX_unload(PKCS11_CTX *ctx) = 0;
    virtual void P11_PKCS11_CTX_free(PKCS11_CTX *ctx) = 0;
};

/**
 * GMock class to mock the above interface.
 *
 */
class LibP11Mock : public LibP11MockInterface
{
public:
    MOCK_METHOD0(P11_PKCS11_CTX_new, PKCS11_CTX *(void));
    MOCK_METHOD2(P11_PKCS11_CTX_load, int(PKCS11_CTX *ctx, const char *ident));

    MOCK_METHOD3(P11_PKCS11_enumerate_slots,
                 int(PKCS11_CTX *ctx, PKCS11_SLOT **slotsp, unsigned int *nslotsp));
    MOCK_METHOD3(P11_PKCS11_release_all_slots,
                 void(PKCS11_CTX *ctx, PKCS11_SLOT *slots, unsigned int nslots));
    MOCK_METHOD3(P11_PKCS11_find_token,
                 PKCS11_SLOT *(PKCS11_CTX *ctx, PKCS11_SLOT *slots, unsigned int nslots));

    /* Session and Login */
    MOCK_METHOD2(P11_PKCS11_open_session, int(PKCS11_SLOT *slot, int rw));
    MOCK_METHOD3(P11_PKCS11_login, int(PKCS11_SLOT *slot, int so, const char *pin));
    MOCK_METHOD1(P11_PKCS11_logout, int(PKCS11_SLOT *slot));
    MOCK_METHOD3(P11_PKCS11_is_logged_in, int(PKCS11_SLOT *slot, int so, int *res));

    /* Key Management */
    MOCK_METHOD5(
            P11_PKCS11_store_private_key,
            int(PKCS11_TOKEN *token, EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len));
    MOCK_METHOD5(
            P11_PKCS11_store_public_key,
            int(PKCS11_TOKEN *token, EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len));
    MOCK_METHOD6(P11_PKCS11_generate_key,
                 int(PKCS11_TOKEN *token,
                     int algorithm,
                     unsigned int bits,
                     char *label,
                     unsigned char *id,
                     size_t id_len));

    /* Clean-up Functions */
    MOCK_METHOD1(P11_PKCS11_CTX_unload, void(PKCS11_CTX *ctx));
    MOCK_METHOD1(P11_PKCS11_CTX_free, void(PKCS11_CTX *ctx));
};

/**
 * Wrap instances of the LibP11Mock
 * inside static members of this class.
 *
 * This gets rid of the need for a singleton and all
 * the realted problems.
 */
class LibP11MockManager
{
public:
    /**
     * Access the P11LibMock instance currently
     * maintained. Create a new one, if none is present.
     */
    static ::testing::NiceMock<LibP11Mock> &getMockInterface();

    /**
     * Reset the current LibP11Mock instance
     * maintained within this class.
     */
    static void resetMock();

    /**
     * Destroy current mock object to trigger gmock call analysis
     */
    static void destroy();

private:
    static std::unique_ptr<::testing::NiceMock<LibP11Mock>> _mock;

    /* Unsure how much parallization happens with regard to the tests
     * but let's be safe
     */
    static std::mutex _mutex;
};

}  // namespace p11
}  // namespace mococrw
