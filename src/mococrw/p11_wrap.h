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

#include "openssl_wrap.h"
#include "p11_lib.h"
#include "util.h"

namespace mococrw
{
namespace p11
{
/**
 * Template to wrap LibP11 free/destroy functions
 * into a functor so that a std::unique_ptr
 * can use them upon being out-of-scope.
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
 * This exception is thrown by all methods when a LibP11 error occurs.
 */
class P11Exception final : public openssl::OpenSSLException
{
    // Note, pkcs11_CTX_new() internally loads LibP11 error strings,
    // i.e., it invokes ERR_load_PKCS11_strings(). We therefore
    // don't trigger the loading ourselves.

public:
    template <class StringType>
    explicit P11Exception(StringType &&message) : OpenSSLException(message)
    {
    }

    /**
     * Generate an exception with the defalt LibP11 error-string
     * as message. Internally, LibP11 uses OpenSSL's error handling framework,
     * and therefore we simply extend OpenSSLException.
     *
     */
    P11Exception() : OpenSSLException() {}

    /**
     * Error Strings.
     *
     * These are declared here to reduce string duplication as well as facilitate
     * tests that check exceptions.
     */
    static const std::string nullCtxExceptionString;
    static const std::string nullSlotListExceptionString;
    static const std::string nullTokenExceptionString;
    static const std::string mismatchLoginExceptionString;
};

/*
 * Wrap all the pointer-types returned by LibP11.
 */

using P11_PKCS11_CTX_Ptr = std::shared_ptr<PKCS11_CTX>;
using P11_PKCS11_SLOT_LIST_PTR = std::shared_ptr<PKCS11_SLOT>;

/* The memory referred to by these pointer types live out-of-scope of their pointers.
 * Therefore, we leverage the aliasing constructor of shared pointers when the following
 * smart pointer types are created.
 */
using P11_PKCS11_SLOT_PTR = std::shared_ptr<PKCS11_SLOT>;
using P11_PKCS11_TOKEN_PTR = std::shared_ptr<PKCS11_TOKEN>;

/**
 * Details information related to a slot list, obtained via enumeration of HSM.
 */
class P11_SlotInfo
{
public:
    P11_SlotInfo(P11_PKCS11_CTX_Ptr ctx);

    struct SlotListDeleter
    {
        SlotListDeleter(P11_PKCS11_CTX_Ptr ctx, int numSlots) : _ctx(ctx), _numSlots(numSlots) {}
        void operator()(PKCS11_SLOT *);

        P11_PKCS11_CTX_Ptr _ctx;
        int _numSlots;
    };

    /**
     * Finds the slot of a token on the HSM.
     */
    P11_PKCS11_SLOT_PTR findSlot();

private:
    P11_PKCS11_CTX_Ptr _ctx;             // The context associated with the slot information.
    P11_PKCS11_SLOT_LIST_PTR _slotList;  // Array consisting of slot descriptors on the HSM.
    unsigned int _numSlots;              // The size of the array, i.e., the number of slots.
};

/**
 * Session mode denotes whether to open a session in read/write mode.
 */
enum SessionMode { ReadOnly = 0, ReadWrite = 1 };

class P11_Session
{
public:
    P11_Session(P11_PKCS11_SLOT_PTR slot, const std::string &pin, SessionMode mode);
    ~P11_Session();  // After session is made out-of-scope, trigger logout.

    /* Returns the token descriptor associated with the passed slot. */
    P11_PKCS11_TOKEN_PTR getTokenFromSlot();

private:
    P11_PKCS11_SLOT_PTR _slot;

    /* Opens a sessions with the passed slot. */
    void openSession(SessionMode mode);

    /* Performs a user login to the HSM. This function performs a user login and not an SO login. */
    void login(const std::string &pin);

    /* Performs a user logout from the HSM. This function only performs a user logout, and not an SO
     * logout. */
    void logout();

    /* Returns true if a user is currently logged in. */
    bool isLoggedIn();
};

/* Below is the "wrapped" LibP11 library. By convention, all functions start with an
 * underscore to visually distinguish them from the methods of the class P11Lib and
 * from the native LibP11 methods.
 */

/**
 * Returns a new and loaded PKCS11 context for HSM interaction.
 *
 * @param module The PKCS#11 module filename.
 * @return A new PKCS11 context.
 */
P11_PKCS11_CTX_Ptr _PKCS11_CTX_create(const std::string &module);

/**
 * Stores a private key inside the HSM.
 *
 * @param session The session used to store the private key.
 * @param pk The key to store.
 * @param label The label of the key to store.
 * @param id The ID of the key to store.
 */
void _PKCS11_store_private_key(P11_Session &session,
                               EVP_PKEY *pk,
                               const std::string &label,
                               const std::string &id);

/**
 * Stores a public key inside the HSM.
 *
 * @param session The session used to store the public key.
 * @param pk The key to store.
 * @param label The label of the key to store.
 * @param id The ID of the key to store.
 */
void _PKCS11_store_public_key(P11_Session &session,
                              EVP_PKEY *pk,
                              const std::string &label,
                              const std::string &id);

/**
 * Generates a key inside the HSM.
 *
 * @param session The session used to generate the key.
 * @param bits The size of the modulus in bits.
 * @param label The label of the generated key.
 * @param id The ID of the generated key.
 *
 * \note Due to limited support offered by LibP11, this function only generates RSA keys.
 */
void _PKCS11_generate_key(P11_Session &session,
                          unsigned int bits,
                          const std::string &label,
                          const std::string &id);

}  // namespace p11
}  // namespace mococrw
