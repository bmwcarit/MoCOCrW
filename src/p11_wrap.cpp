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
 * Implementation of P11SlotInfo
 */

P11SlotInfo::P11SlotInfo(P11_PKCS11_CTX_SharedPtr ctx) : _ctx(ctx), _slotList(nullptr), _numSlots(0)
{
    PKCS11_SLOT *slots;

    // Enumerate slots to obtain slot information.
    P11IsNonNegative::callChecked(
            lib::LibP11::P11_PKCS11_enumerate_slots, _ctx.get(), &slots, &_numSlots);

    // If the returned slot list is NULL, we cannot continue!
    if (slots == nullptr) {
        throw P11Exception("Slot enumeration erroneously returned a null slot list");
    }

    SlotListDeleter deleter(_ctx, _numSlots);
    _slotList = P11_PKCS11_SLOT_LIST_SharedPtr(slots, deleter);
}

void P11SlotInfo::SlotListDeleter::operator()(PKCS11_SLOT *slotList)
{
    lib::LibP11::P11_PKCS11_release_all_slots(_ctx.get(), slotList, _numSlots);
}

P11_PKCS11_SLOT_SharedPtr P11SlotInfo::findSlot()
{
    auto raw_slot = P11CallPtr::callChecked(
            lib::LibP11::P11_PKCS11_find_token, _ctx.get(), _slotList.get(), _numSlots);

    // The memory of the slot is owned by the slot list. Therefore, use shared pointer's alias
    // constructor.
    return P11_PKCS11_SLOT_SharedPtr(_slotList, raw_slot);
}

/***********************************************************************************
 * Implementation of P11Session
 */

P11Session::P11Session(P11_PKCS11_SLOT_SharedPtr slot, const std::string &pin, SessionMode mode)
        : _slot(slot)
{
    openSession(mode);
    login(pin);
}

P11Session::~P11Session() { logout(); }

P11_PKCS11_TOKEN_SharedPtr P11Session::getTokenFromSessionSlot()
{
    // Simply obtain the token via the slot's data structure.
    if (_slot.get()->token == nullptr) {
        throw P11Exception("Slot is erroneously associated with a null token");
    }

    // The memory of the token is owned by the slot. Therefore, use shared pointer's alias
    // constructor.
    return P11_PKCS11_TOKEN_SharedPtr(_slot, _slot.get()->token);
}

void P11Session::openSession(SessionMode mode)
{
    P11IsNonNegative::callChecked(
            lib::LibP11::P11_PKCS11_open_session, _slot.get(), mode /* Denotes read/write mode. */);
}

void P11Session::login(const std::string &pin)
{
    P11IsNonNegative::callChecked(lib::LibP11::P11_PKCS11_login,
                                  _slot.get(),
                                  0 /* Always login as normal user. */,
                                  pin.c_str());
}

void P11Session::logout()
{
    // Don't check return value and potentially raise an exception as this function
    // is used by the destructor, which shouldn't throw.
    lib::LibP11::P11_PKCS11_logout(_slot.get());
}

/***********************************************************************************
 * Implementation of API functions.
 */

/* Destroys a PKCS11 context by first unloading it, and then freeing it. */
static void _PKCS11_CTX_destroy(PKCS11_CTX *ctx)
{
    lib::LibP11::P11_PKCS11_CTX_unload(ctx);
    lib::LibP11::P11_PKCS11_CTX_free(ctx);
}

P11_PKCS11_CTX_SharedPtr _PKCS11_CTX_create(const std::string &module)
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
    return P11_PKCS11_CTX_SharedPtr{ctx, _PKCS11_CTX_destroy};
}

static std::vector<unsigned char> parseID(const std::string &idHexString)
{
    /* We require IDs to be represented as hex strings from the user.
     * LibP11 does the necessary pre-processing, such as unhexing, on IDs
     * only when invoked via OpenSSL's Engine API. However, when interacting directly
     * with LibP11 API, like we do here, this pre-processing is not performed. To make
     * matters worse, LibP11 does not export its internal
     * pre-processing function. We therefore begin to re-implement it here.
     */
    auto parsedIDStr = boost::algorithm::unhex(idHexString);
    std::vector<unsigned char> parsedID;
    std::copy(parsedIDStr.begin(), parsedIDStr.end(), std::back_inserter(parsedID));

    return parsedID;
}

void _PKCS11_store_private_key(P11Session_SharedPtr session,
                               EVP_PKEY *pk,
                               const std::string &label,
                               const std::string &id)
{
    auto parsedID = parseID(id);
    P11IsNonNegative::callChecked(lib::LibP11::P11_PKCS11_store_private_key,
                                  session->getTokenFromSessionSlot().get(),
                                  pk,
                                  const_cast<char *>(label.c_str()),
                                  parsedID.data(),
                                  parsedID.size());
}

void _PKCS11_store_public_key(P11Session_SharedPtr session,
                              EVP_PKEY *pk,
                              const std::string &label,
                              const std::string &id)
{
    auto parsedID = parseID(id);
    P11IsNonNegative::callChecked(lib::LibP11::P11_PKCS11_store_public_key,
                                  session->getTokenFromSessionSlot().get(),
                                  pk,
                                  const_cast<char *>(label.c_str()),
                                  parsedID.data(),
                                  parsedID.size());
}

void _PKCS11_generate_rsa_key(P11Session_SharedPtr session,
                              unsigned int bits,
                              const std::string &label,
                              const std::string &id)
{
    auto parsedID = parseID(id);

    // Note, PKCS11_generate_key() function only generates RSA keys.
    // It is deprecated but no alternative has been implemented yet.
    // See: https://github.com/OpenSC/libp11/pull/378
    P11IsNonNegative::callChecked(lib::LibP11::P11_PKCS11_generate_key,
                                  session->getTokenFromSessionSlot().get(),
                                  0 /* Currently, algorithm is ignored by LibP11. */,
                                  bits,
                                  const_cast<char *>(label.c_str()),
                                  parsedID.data(),
                                  parsedID.size());
}

}  // namespace p11
}  // namespace mococrw
