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

/*
 * This file is the only place where we should see any
 * "vanilla" LibP11 methods whatsoever. Any other
 * translation unit should use the methods exposed via
 * P11Lib.
 *
 * Moreover, the methods exposed by P11Lib should only
 * be used in p11_wrap.cpp and p11_wrap.h.
 *
 */

#include "mococrw/p11_lib.h"

namespace mococrw
{
namespace p11
{
namespace lib
{
/* The implementation of P11Lib class members.
 *
 *
 * Any method here simply forwards to an equivalent LibP11 method
 */

PKCS11_CTX *LibP11::P11_PKCS11_CTX_new(void) noexcept { return PKCS11_CTX_new(); }

int LibP11::P11_PKCS11_CTX_load(PKCS11_CTX *ctx, const char *ident) noexcept
{
    return PKCS11_CTX_load(ctx, ident);
}

int LibP11::P11_PKCS11_enumerate_slots(PKCS11_CTX *ctx,
                                       PKCS11_SLOT **slotsp,
                                       unsigned int *nslotsp) noexcept
{
    return PKCS11_enumerate_slots(ctx, slotsp, nslotsp);
}

void LibP11::P11_PKCS11_release_all_slots(PKCS11_CTX *ctx,
                                          PKCS11_SLOT *slots,
                                          unsigned int nslots) noexcept
{
    PKCS11_release_all_slots(ctx, slots, nslots);
}

PKCS11_SLOT *LibP11::P11_PKCS11_find_token(PKCS11_CTX *ctx,
                                           PKCS11_SLOT *slots,
                                           unsigned int nslots) noexcept
{
    return PKCS11_find_token(ctx, slots, nslots);
}

/* Session and Login */
int LibP11::P11_PKCS11_open_session(PKCS11_SLOT *slot, int rw) noexcept
{
    return PKCS11_open_session(slot, rw);
}

int LibP11::P11_PKCS11_login(PKCS11_SLOT *slot, int so, const char *pin) noexcept
{
    return PKCS11_login(slot, so, pin);
}

int LibP11::P11_PKCS11_logout(PKCS11_SLOT *slot) noexcept { return PKCS11_logout(slot); }

int LibP11::P11_PKCS11_is_logged_in(PKCS11_SLOT *slot, int so, int *res) noexcept
{
    return PKCS11_is_logged_in(slot, so, res);
}

/* Key Management */
int LibP11::P11_PKCS11_store_private_key(
        PKCS11_TOKEN *token, EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len) noexcept
{
    return PKCS11_store_private_key(token, pk, label, id, id_len);
}

int LibP11::P11_PKCS11_store_public_key(
        PKCS11_TOKEN *token, EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len) noexcept
{
    return PKCS11_store_public_key(token, pk, label, id, id_len);
}

int LibP11::P11_PKCS11_generate_key(PKCS11_TOKEN *token,
                                    int algorithm,
                                    unsigned int bits,
                                    char *label,
                                    unsigned char *id,
                                    size_t id_len) noexcept
{
    return PKCS11_generate_key(token, algorithm, bits, label, id, id_len);
}

void LibP11::P11_PKCS11_CTX_unload(PKCS11_CTX *ctx) noexcept { PKCS11_CTX_unload(ctx); }

void LibP11::P11_PKCS11_CTX_free(PKCS11_CTX *ctx) noexcept { PKCS11_CTX_free(ctx); }

}  // namespace lib
}  // namespace p11
}  // namespace mococrw
