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
#include <cstddef>

#include <gmock/gmock.h>

#include "mococrw/p11_wrap.h"
#include "p11_lib_mock.h"

namespace mococrw
{
namespace p11
{
std::unique_ptr<::testing::NiceMock<LibP11Mock>> LibP11MockManager::_mock{nullptr};
std::mutex LibP11MockManager::_mutex{};

/*
 * If there is no mock yet, we create a new one.
 */
testing::NiceMock<LibP11Mock> &LibP11MockManager::getMockInterface()
{
    if (!_mock) {
        resetMock();
    }

    return *_mock;
}

void LibP11MockManager::resetMock()
{
    std::lock_guard<std::mutex> _lock(_mutex);
    _mock = std::make_unique<::testing::NiceMock<LibP11Mock>>();
}

void LibP11MockManager::destroy()
{
    std::lock_guard<std::mutex> _lock(_mutex);
    // NOLINTNEXTLINE(clang-analyzer-optin.cplusplus.VirtualCall)
    _mock.reset();
}

namespace lib
{
/**
 * Provide implementations for the LibP11 members that forward
 * to the mock object.
 */

PKCS11_CTX *LibP11::P11_PKCS11_CTX_new(void) noexcept
{
    return LibP11MockManager::getMockInterface().P11_PKCS11_CTX_new();
}

int LibP11::P11_PKCS11_CTX_load(PKCS11_CTX *ctx, const char *ident) noexcept
{
    return LibP11MockManager::getMockInterface().P11_PKCS11_CTX_load(ctx, ident);
}

int LibP11::P11_PKCS11_enumerate_slots(PKCS11_CTX *ctx,
                                       PKCS11_SLOT **slotsp,
                                       unsigned int *nslotsp) noexcept
{
    return LibP11MockManager::getMockInterface().P11_PKCS11_enumerate_slots(ctx, slotsp, nslotsp);
}

void LibP11::P11_PKCS11_release_all_slots(PKCS11_CTX *ctx,
                                          PKCS11_SLOT *slots,
                                          unsigned int nslots) noexcept
{
    LibP11MockManager::getMockInterface().P11_PKCS11_release_all_slots(ctx, slots, nslots);
}

PKCS11_SLOT *LibP11::P11_PKCS11_find_token(PKCS11_CTX *ctx,
                                           PKCS11_SLOT *slots,
                                           unsigned int nslots) noexcept
{
    return LibP11MockManager::getMockInterface().P11_PKCS11_find_token(ctx, slots, nslots);
}

/* Session and Login */
int LibP11::P11_PKCS11_open_session(PKCS11_SLOT *slot, int rw) noexcept
{
    return LibP11MockManager::getMockInterface().P11_PKCS11_open_session(slot, rw);
}

int LibP11::P11_PKCS11_login(PKCS11_SLOT *slot, int so, const char *pin) noexcept
{
    return LibP11MockManager::getMockInterface().P11_PKCS11_login(slot, so, pin);
}

int LibP11::P11_PKCS11_logout(PKCS11_SLOT *slot) noexcept
{
    return LibP11MockManager::getMockInterface().P11_PKCS11_logout(slot);
}

int LibP11::P11_PKCS11_is_logged_in(PKCS11_SLOT *slot, int so, int *res) noexcept
{
    return LibP11MockManager::getMockInterface().P11_PKCS11_is_logged_in(slot, so, res);
}

/* Key Management */
int LibP11::P11_PKCS11_store_private_key(
        PKCS11_TOKEN *token, EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len) noexcept
{
    return LibP11MockManager::getMockInterface().P11_PKCS11_store_private_key(
            token, pk, label, id, id_len);
}

int LibP11::P11_PKCS11_store_public_key(
        PKCS11_TOKEN *token, EVP_PKEY *pk, char *label, unsigned char *id, size_t id_len) noexcept
{
    return LibP11MockManager::getMockInterface().P11_PKCS11_store_public_key(
            token, pk, label, id, id_len);
}

int LibP11::P11_PKCS11_generate_key(PKCS11_TOKEN *token,
                                    int algorithm,
                                    unsigned int bits,
                                    char *label,
                                    unsigned char *id,
                                    size_t id_len) noexcept
{
    return LibP11MockManager::getMockInterface().P11_PKCS11_generate_key(
            token, algorithm, bits, label, id, id_len);
}

void LibP11::P11_PKCS11_CTX_unload(PKCS11_CTX *ctx) noexcept
{
    LibP11MockManager::getMockInterface().P11_PKCS11_CTX_unload(ctx);
}

void LibP11::P11_PKCS11_CTX_free(PKCS11_CTX *ctx) noexcept
{
    return LibP11MockManager::getMockInterface().P11_PKCS11_CTX_free(ctx);
}

}  // namespace lib
}  // namespace p11
}  // namespace mococrw
