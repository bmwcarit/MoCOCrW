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
 * methods from LibP11. Any other code should use
 * the more high-level methods declared and define in
 * p11_wrap.cpp and p11_wrap.h.
 *
 */

#include <boost/algorithm/hex.hpp>
#include <cassert>
#include <cstddef> /* this has to come before cppc (bug in boost) */
#include <exception>

#include <cppc/checkcall.hpp>
#include "mococrw/openssl_wrap.h"
#include "mococrw/p11_wrap.h"

namespace mococrw
{
namespace p11
{
// Initialise error strings of LibP11 wrapper:
const std::string P11Exception::nullCtxExceptionString = "Found NULL PKCS11 Context";
const std::string P11Exception::nullSlotListExceptionString = "Found NULL Slot List";
const std::string P11Exception::nullTokenExceptionString = "Found NULL Token";
const std::string P11Exception::mismatchLoginExceptionString = "Login/Logout Mismatch Detected";

/**
 * This struct is used by CWrap to
 * determine how to react to an error
 * when performing a LibP11 call.
 */
struct P11ExceptionErrorPolicy
{
    template <class Rv>
    static void handleError(const Rv &);
};

/**
 * Throw a P11 exception upon error.
 *
 * This method fetches the error string and throws an exception
 * with the corresponding message.
 */
template <class Rv>
void P11ExceptionErrorPolicy::handleError(const Rv & /* unused */)
{
    throw P11Exception();
}

// For checking return values:
using P11CallPtr =
        ::cppc::CallCheckContext<::cppc::IsNotNullptrReturnCheckPolicy, P11ExceptionErrorPolicy>;
using P11IsNonNegative =
        ::cppc::CallCheckContext<::cppc::IsNotNegativeReturnCheckPolicy, P11ExceptionErrorPolicy>;

/***********************************************************************************
 * Implementation of P11_SlotInfo
 */

P11_SlotInfo::P11_SlotInfo(P11_PKCS11_CTX_Ptr ctx) : _ctx(ctx), _slotList(nullptr), _numSlots(0)
{
    PKCS11_SLOT *slots;

    // Enumerate slots to obtain slot information.
    P11IsNonNegative::callChecked(
            lib::LibP11::P11_PKCS11_enumerate_slots, _ctx.get(), &slots, &_numSlots);

    // If the returned slot list is NULL, we cannot continue!
    if (slots == nullptr) {
        throw P11Exception(P11Exception::nullSlotListExceptionString);
    }

    SlotListDeleter deleter(_ctx, _numSlots);
    _slotList = P11_PKCS11_SLOT_LIST_PTR(slots, deleter);
}

void P11_SlotInfo::SlotListDeleter::operator()(PKCS11_SLOT *slotList)
{
    if (slotList == nullptr) {
        throw P11Exception(P11Exception::nullSlotListExceptionString);
    }

    lib::LibP11::P11_PKCS11_release_all_slots(_ctx.get(), slotList, _numSlots);
}

P11_PKCS11_SLOT_PTR P11_SlotInfo::findSlot()
{
    PKCS11_SLOT *raw_slot = P11CallPtr::callChecked(
            lib::LibP11::P11_PKCS11_find_token, _ctx.get(), _slotList.get(), _numSlots);

    // Leverage aliasing.
    return P11_PKCS11_SLOT_PTR(_slotList, raw_slot);
}

/***********************************************************************************
 * Implementation of P11_Session
 */

P11_Session::P11_Session(P11_PKCS11_SLOT_PTR slot, const std::string &pin, SessionMode mode)
        : _slot(slot)
{
    openSession(mode);
    login(pin);
}

P11_Session::~P11_Session() { logout(); }

P11_PKCS11_TOKEN_PTR P11_Session::getTokenFromSlot()
{
    // Simply obtain the token via the slot's data structure.
    if (_slot.get()->token == nullptr) {
        throw P11Exception(P11Exception::nullTokenExceptionString);
    }

    // Leverage aliasing.
    return P11_PKCS11_TOKEN_PTR(_slot, _slot.get()->token);
}

void P11_Session::openSession(SessionMode mode)
{
    P11IsNonNegative::callChecked(
            lib::LibP11::P11_PKCS11_open_session, _slot.get(), mode /* Denotes read/write mode. */);
}

void P11_Session::login(const std::string &pin)
{
    if (isLoggedIn()) {
        // Weird: We are trying to log in, when we are logged in already.
        throw P11Exception(P11Exception::mismatchLoginExceptionString);
    }

    P11IsNonNegative::callChecked(lib::LibP11::P11_PKCS11_login,
                                  _slot.get(),
                                  0 /* Always login as normal user. */,
                                  pin.c_str());
}

void P11_Session::logout()
{
    if (!isLoggedIn()) {
        // Weird: We are trying to log out, when we are logged out already.
        throw P11Exception(P11Exception::mismatchLoginExceptionString);
    }

    P11IsNonNegative::callChecked(lib::LibP11::P11_PKCS11_logout, _slot.get());
}

bool P11_Session::isLoggedIn()
{
    int result;
    P11IsNonNegative::callChecked(
            lib::LibP11::P11_PKCS11_is_logged_in, _slot.get(), 0 /* Check normal user. */, &result);

    // Result is 1 if logged in.
    return result == 1;
}

/***********************************************************************************
 * Implementation of API functions.
 */

/* Destroys a PKCS11 context by first unloading it, and then freeing it. */
static void _PKCS11_CTX_destroy(PKCS11_CTX *ctx)
{
    if (ctx == nullptr) {
        throw P11Exception(P11Exception::nullCtxExceptionString);
    }
    lib::LibP11::P11_PKCS11_CTX_unload(ctx);
    lib::LibP11::P11_PKCS11_CTX_free(ctx);
}

P11_PKCS11_CTX_Ptr _PKCS11_CTX_create(const std::string &module)
{
    PKCS11_CTX *ctx = P11CallPtr::callChecked(lib::LibP11::P11_PKCS11_CTX_new);
    try {
        P11IsNonNegative::callChecked(lib::LibP11::P11_PKCS11_CTX_load, ctx, module.c_str());
    } catch (const P11Exception &e) {
        // Free the ctx if loading failed and then throw.
        lib::LibP11::P11_PKCS11_CTX_free(ctx);
        throw;
    }

    // Create shared pointer which will unload and free the ctx automatically.
    return P11_PKCS11_CTX_Ptr{ctx, _PKCS11_CTX_destroy};
}

static std::string parseID(const std::string &idHexString)
{
    /* We require IDs to be represented as hex strings from the user.
     * LibP11 does the necessary pre-processing, such as unhexing, on IDs
     * only when invoked via OpenSSL's Engine API. However, when interacting directly
     * with LibP11 API, like we do here, this pre-processing is not performed. To make
     * matters worse, LibP11 does not export its internal
     * pre-processing function. We therefore begin to re-implement it here.
     */
    auto parsedID = boost::algorithm::unhex(idHexString);
    return parsedID;
}

void _PKCS11_store_private_key(P11_Session &session,
                               EVP_PKEY *pk,
                               const std::string &label,
                               const std::string &id)
{
    std::string parsedStrID = parseID(id);
    unsigned char *parsedID =
            reinterpret_cast<unsigned char *>(const_cast<char *>(parsedStrID.c_str()));

    P11IsNonNegative::callChecked(lib::LibP11::P11_PKCS11_store_private_key,
                                  session.getTokenFromSlot().get(),
                                  pk,
                                  const_cast<char *>(label.c_str()),
                                  parsedID,
                                  parsedStrID.size());
}

void _PKCS11_store_public_key(P11_Session &session,
                              EVP_PKEY *pk,
                              const std::string &label,
                              const std::string &id)
{
    auto parsedStrID = parseID(id);
    unsigned char *parsedID =
            reinterpret_cast<unsigned char *>(const_cast<char *>(parsedStrID.c_str()));

    P11IsNonNegative::callChecked(lib::LibP11::P11_PKCS11_store_public_key,
                                  session.getTokenFromSlot().get(),
                                  pk,
                                  const_cast<char *>(label.c_str()),
                                  parsedID,
                                  parsedStrID.size());
}

void _PKCS11_generate_key(P11_Session &session,
                          unsigned int bits,
                          const std::string &label,
                          const std::string &id)
{
    std::string parsedStrID = parseID(id);
    unsigned char *parsedID =
            reinterpret_cast<unsigned char *>(const_cast<char *>(parsedStrID.c_str()));

    // Note, PKCS11_generate_key() function only generates RSA keys.
    // It is deprecated but no alternative has been implemented yet.
    // See: https://github.com/OpenSC/libp11/pull/378
    P11IsNonNegative::callChecked(lib::LibP11::P11_PKCS11_generate_key,
                                  session.getTokenFromSlot().get(),
                                  0 /* Currently, algorithm is ignored by LibP11. */,
                                  bits,
                                  const_cast<char *>(label.c_str()),
                                  parsedID,
                                  parsedStrID.size());
}

}  // namespace p11
}  // namespace mococrw
