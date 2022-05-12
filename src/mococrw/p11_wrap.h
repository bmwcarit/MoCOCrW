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

#include "p11_lib.h"
#include "util.h"

namespace mococrw
{
namespace p11
{
/**
 * Template to wrap OpenSSLs "_free" functions
 * into a functor so that a std::unique_ptr
 * can use them.
 */
template <class R, class P, R(Func)(P *)>
struct P11Deleter
{
    template <class T>
    void operator()(T *ptr) const noexcept
    {
        if (ptr) {
            Func(ptr);
        }
    }
};

/**
 * An Exception for LibP11 errors.
 *
 * This exception is thrown by all methods when an OpenSSL error occurs.
 */
class P11Exception final : public std::exception
{
public:
    template <class StringType>
    explicit P11Exception(StringType &&message) : _message{std::forward<StringType>(message)}
    {
    }

    /**
     * Generate an exception with the defalt LibP11 error-string
     * as message.
     *
     */
    P11Exception() : _message{generateP11ErrorString()} {}

    const char *what() const noexcept override { return _message.c_str(); }

private:
    static std::string generateP11ErrorString();
    std::string _message;
};

/*
 * Wrap all the pointer-types returned by LibP11.
 */

using P11_PKCS11_CTX_Ptr =
        std::unique_ptr<PKCS11_CTX, P11Deleter<void, PKCS11_CTX, lib::LibP11::P11_PKCS11_CTX_free>>;

/*
 * The memory referred to by these pointer types live out of scope of their pointers.
 * Therefore, simply wrap the C pointer, without use of smart pointer (this is a bit ugly).
 */
using P11_PKCS11_SLOT_PTR = PKCS11_SLOT *;
using P11_PKCS11_TOKEN_PTR = PKCS11_TOKEN *;

/* Below is the "wrapped" LibP11 library. By convention, all functions start with an
 * underscore to visually distinguish them from the methods of the class P11Lib and
 * from the native LibP11 methods.
 */

/**
 * Returns a new PKCS11 context for HSM interaction.
 */
P11_PKCS11_CTX_Ptr _PKCS11_CTX_new(void);

/**
 * Loads the PKCS11 module to use.
 *
 * @param ctx The current context obtained via _PKCS11_CTX_new().
 * @param module The PKCS#11 module filename.
 */
void _PKCS11_CTX_load(PKCS11_CTX *ctx, const std::string &module);

struct P11_SlotInfo
{
    PKCS11_SLOT *_slots;     // Array consisting of slot descriptors on the HSM.
    unsigned int _numSlots;  // The size of the array, i.e., the number of slots.

    P11_SlotInfo();
    P11_SlotInfo(PKCS11_SLOT *slots, unsigned int numSlots);
};

/**
 * Obtains information of all current slots on the HSM.
 *
 * @param ctx The current context obtained via _PKCS11_CTX_new().
 */
P11_SlotInfo _PKCS11_enumerate_slots(PKCS11_CTX *ctx);

/**
 * Destroys slot information obtained by _PKCS11_enumerate_slots().
 *
 * @param ctx The current context obtained via _PKCS11_CTX_new().
 * @param slotInfo The slot-list information to destroy.
 */
void _PKCS11_release_all_slots(PKCS11_CTX *ctx, P11_SlotInfo &slotInfo);

/**
 * Finds a token on the HSM according to the passed slot information \p slotInfo.
 *
 * @param ctx The current context obtained via _PKCS11_CTX_new().
 * @param slotInfo Slot information obtained via _PKCS11_enumerate_slots().
 */
P11_PKCS11_SLOT_PTR _PKCS11_find_token(PKCS11_CTX *ctx, P11_SlotInfo &slotInfo);

/**
 * Returns the token descriptor associated with \p slot.
 *
 * @param slot The slot of the returned token.
 */
P11_PKCS11_TOKEN_PTR _PKCS11_getTokenFromSlot(PKCS11_SLOT *slot);

enum SessionMode { ReadOnly = 0, ReadWrite = 1 };

/**
 * Opens a sessions with the passed \p slot.
 *
 * @param slot The slot to open session with.
 * @param rw Whether to open the session in read/write mode. Set to != 0
 * if read/write mode is required.
 */
void _PKCS11_open_session(PKCS11_SLOT *slot, SessionMode mode);

/**
 * Performs a user login to the HSM.
 *
 * @param slot The slot to consider for login.
 * @param pin The pin to perform the login.
 *
 * \note This function performs a user login and not an SO login.
 */
void _PKCS11_login(PKCS11_SLOT *slot, const std::string &pin);

/**
 * Performs a user logout from the HSM.
 *
 * @param slot The slot logout from.
 *
 * \note This function only performs a user logout, and not an SO logout.
 */
void _PKCS11_logout(PKCS11_SLOT *slot);

/**
 * Returns true if a user is currently logged in.
 *
 * @param slot The slot to check login status.
 */
bool _PKCS11_is_logged_in(PKCS11_SLOT *slot);

/**
 * Stores a private key inside the HSM.
 *
 * @param token The token used to store the private key.
 * @param pk The key to store.
 * @param label The label of the key to store.
 * @param id The ID of the key to store.
 */
void _PKCS11_store_private_key(PKCS11_TOKEN *token,
                               EVP_PKEY *pk,
                               const std::string &label,
                               const std::string &id);

/**
 * Stores a public key inside the HSM.
 *
 * @param token The token used to store the public key.
 * @param pk The key to store.
 * @param label The label of the key to store.
 * @param id The ID of the key to store.
 */
void _PKCS11_store_public_key(PKCS11_TOKEN *token,
                              EVP_PKEY *pk,
                              const std::string &label,
                              const std::string &id);

/**
 * Generates a key inside the HSM.
 *
 * @param token The token used to generate the key.
 * @param bits The size of the modulus in bits.
 * @param label The label of the generated key.
 * @param id The ID of the generated key.
 *
 * \note Due to limited support offered by LibP11, this function only generates RSA keys.
 */
void _PKCS11_generate_key(PKCS11_TOKEN *token,
                          unsigned int bits,
                          const std::string &label,
                          const std::string &id);

/**
 * Unloads the PKCS11 module.
 */
void _PKCS11_CTX_unload(PKCS11_CTX *ctx);

}  // namespace p11
}  // namespace mococrw
