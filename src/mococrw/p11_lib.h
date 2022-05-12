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

extern "C" {
#include <libp11.h>
}

namespace mococrw
{
namespace p11
{
namespace lib
{
/**
 * Thin wrapper around the "naked" P11 library (namely libp11).
 *
 * Prefix all method names with 'P11_' to distinguish them from their
 * LibP11 counterparts.
 */
class LibP11
{
public:
    /* Initialisation */
    static PKCS11_CTX *P11_PKCS11_CTX_new(void) noexcept;
    static int P11_PKCS11_CTX_load(PKCS11_CTX *ctx, const char *ident) noexcept;

    /* Slot and Token Management */
    static int P11_PKCS11_enumerate_slots(PKCS11_CTX *ctx,
                                          PKCS11_SLOT **slotsp,
                                          unsigned int *nslotsp) noexcept;
    static void P11_PKCS11_release_all_slots(PKCS11_CTX *ctx,
                                             PKCS11_SLOT *slots,
                                             unsigned int nslots) noexcept;
    static PKCS11_SLOT *P11_PKCS11_find_token(PKCS11_CTX *ctx,
                                              PKCS11_SLOT *slots,
                                              unsigned int nslots) noexcept;

    /* Session and Login */
    static int P11_PKCS11_open_session(PKCS11_SLOT *slot, int rw) noexcept;
    static int P11_PKCS11_login(PKCS11_SLOT *slot, int so, const char *pin) noexcept;
    static int P11_PKCS11_logout(PKCS11_SLOT *slot) noexcept;
    static int P11_PKCS11_is_logged_in(PKCS11_SLOT *slot, int so, int *res) noexcept;

    /* Key Management */
    static int P11_PKCS11_store_private_key(PKCS11_TOKEN *token,
                                            EVP_PKEY *pk,
                                            char *label,
                                            unsigned char *id,
                                            size_t id_len) noexcept;
    static int P11_PKCS11_store_public_key(PKCS11_TOKEN *token,
                                           EVP_PKEY *pk,
                                           char *label,
                                           unsigned char *id,
                                           size_t id_len) noexcept;
    static int P11_PKCS11_generate_key(PKCS11_TOKEN *token,
                                       int algorithm,
                                       unsigned int bits,
                                       char *label,
                                       unsigned char *id,
                                       size_t id_len) noexcept;

    /* Clean-up Functions */
    static void P11_PKCS11_CTX_unload(PKCS11_CTX *ctx) noexcept;
    static void P11_PKCS11_CTX_free(PKCS11_CTX *ctx) noexcept;
};
}  // namespace lib
}  // namespace p11
}  // namespace mococrw
