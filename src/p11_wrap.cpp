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
std::string P11Exception::generateP11ErrorString()
{
    // Note, pkcs11_CTX_new() internally loads LibP11 error strings,
    // i.e., it invokes ERR_load_PKCS11_strings(). We therefore
    // don't trigger the loading ourselves.
    auto error = openssl::lib::OpenSSLLib::SSL_ERR_get_error();
    auto formatter = boost::format("%s: %d");
    formatter % openssl::lib::OpenSSLLib::SSL_ERR_error_string(error, nullptr) % error;
    return formatter.str();
}

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
 * This method gets the error string and throws an exception
 * with the corresponding message.
 */
template <class Rv>
void P11ExceptionErrorPolicy::handleError(const Rv & /* unused */)
{
    throw P11Exception();
}

using P11CallPtr =
        ::cppc::CallCheckContext<::cppc::IsNotNullptrReturnCheckPolicy, P11ExceptionErrorPolicy>;
using P11IsNonNegative =
        ::cppc::CallCheckContext<::cppc::IsNotNegativeReturnCheckPolicy, P11ExceptionErrorPolicy>;

P11_SlotInfo::P11_SlotInfo() : _slots(nullptr), _numSlots(0) {}

P11_SlotInfo::P11_SlotInfo(PKCS11_SLOT *slots, unsigned int numSlots)
        : _slots(slots), _numSlots(numSlots)
{
}

static std::string parseID(const std::string &idHexString)
{
    /* We require IDs to be represented as hex strings from the user.
     * Libp11 does the necessary pre-processing, such as unhexing, on IDs
     * only when invoked via OpenSSL's Engine API. However, when interacting directly
     * with LibP11 API, like we do here, this pre-processing is not performed. To make
     * matters worse, LibP11 does not export its internal
     * pre-processing function. We therefore begin to re-implement it here.
     */
    auto parsedID = boost::algorithm::unhex(idHexString);
    return parsedID;
}

P11_PKCS11_CTX_Ptr _PKCS11_CTX_new(void)
{
    return P11_PKCS11_CTX_Ptr{P11CallPtr::callChecked(lib::LibP11::P11_PKCS11_CTX_new)};
}

void _PKCS11_CTX_load(PKCS11_CTX *ctx, const std::string &module)
{
    P11IsNonNegative::callChecked(lib::LibP11::P11_PKCS11_CTX_load, ctx, module.c_str());
}

void _PKCS11_CTX_unload(PKCS11_CTX *ctx)
{
    if (ctx == nullptr) {
        throw P11Exception("NULL passed for context that is required to be unloaded");
    }
    lib::LibP11::P11_PKCS11_CTX_unload(ctx);
}

P11_SlotInfo _PKCS11_enumerate_slots(PKCS11_CTX *ctx)
{
    if (ctx == nullptr) {
        throw P11Exception("NULL passed for context when enumerating slots");
    }

    PKCS11_SLOT *slotsp;
    unsigned int nslotsp;
    P11IsNonNegative::callChecked(lib::LibP11::P11_PKCS11_enumerate_slots, ctx, &slotsp, &nslotsp);

    // Based on the information obtained by slot enumaration, we instantiate
    // a corresponding P11_SlotInfo object as a return value.
    P11_SlotInfo slotInfo(slotsp, nslotsp);
    return slotInfo;
}

void _PKCS11_release_all_slots(PKCS11_CTX *ctx, P11_SlotInfo &slotInfo)
{
    if (ctx == nullptr) {
        throw P11Exception("NULL passed for context when releaseing slots");
    }

    if (slotInfo._slots == nullptr) {
        throw P11Exception("NULL list when releaseing slots");
    }

    lib::LibP11::P11_PKCS11_release_all_slots(ctx, slotInfo._slots, slotInfo._numSlots);

    // Finally, clear the object to remove dangling information.
    slotInfo._slots = nullptr;
    slotInfo._numSlots = 0;
}

P11_PKCS11_SLOT_PTR _PKCS11_find_token(PKCS11_CTX *ctx, P11_SlotInfo &slotInfo)
{
    if (ctx == nullptr) {
        throw P11Exception("NULL passed for ctx");
    }

    return P11CallPtr::callChecked(
            lib::LibP11::P11_PKCS11_find_token, ctx, slotInfo._slots, slotInfo._numSlots);
}

P11_PKCS11_TOKEN_PTR _PKCS11_getTokenFromSlot(PKCS11_SLOT *slot)
{
    if (slot == nullptr) {
        throw P11Exception("Cannot retrieve token from NULL slot pointer");
    }

    // Simply obtain the token via the slot's data structure.
    P11_PKCS11_TOKEN_PTR token = slot->token;
    if (token == nullptr) {
        throw P11Exception("Cannot get token. Slot not associated with token");
    }

    return token;
}

void _PKCS11_open_session(PKCS11_SLOT *slot, SessionMode mode)
{
    if (slot == nullptr) {
        throw P11Exception("Cannot open session from NULL slot pointer");
    }

    P11IsNonNegative::callChecked(
            lib::LibP11::P11_PKCS11_open_session, slot, mode /* Denotes read/write mode. */);
}

void _PKCS11_login(PKCS11_SLOT *slot, const std::string &pin)
{
    if (slot == nullptr) {
        throw P11Exception("Cannot login from NULL slot pointer");
    }

    if (_PKCS11_is_logged_in(slot)) {
        throw P11Exception("Mismatch detected; user already logged in");
    }

    P11IsNonNegative::callChecked(
            lib::LibP11::P11_PKCS11_login, slot, 0 /* Always login as normal user. */, pin.c_str());
}

void _PKCS11_logout(PKCS11_SLOT *slot)
{
    if (slot == nullptr) {
        throw P11Exception("Cannot logout from NULL slot pointer");
    }

    if (!_PKCS11_is_logged_in(slot)) {
        throw P11Exception("Mismatch detected; user not logged in to perform logout");
    }

    P11IsNonNegative::callChecked(lib::LibP11::P11_PKCS11_logout, slot);
}

bool _PKCS11_is_logged_in(PKCS11_SLOT *slot)
{
    if (slot == nullptr) {
        throw P11Exception("Cannot check login from NULL slot pointer");
    }

    int result;
    P11IsNonNegative::callChecked(
            lib::LibP11::P11_PKCS11_is_logged_in, slot, 0 /* Check normal user. */, &result);

    // Result is 1 if logged in.
    return result == 1;
}

void _PKCS11_store_private_key(PKCS11_TOKEN *token,
                               EVP_PKEY *pk,
                               const std::string &label,
                               const std::string &id)
{
    std::string parsedStrID = parseID(id);
    unsigned char *parsedID =
            reinterpret_cast<unsigned char *>(const_cast<char *>(parsedStrID.c_str()));

    P11IsNonNegative::callChecked(lib::LibP11::P11_PKCS11_store_private_key,
                                  token,
                                  pk,
                                  const_cast<char *>(label.c_str()),
                                  parsedID,
                                  parsedStrID.size());
}

void _PKCS11_store_public_key(PKCS11_TOKEN *token,
                              EVP_PKEY *pk,
                              const std::string &label,
                              const std::string &id)
{
    auto parsedStrID = parseID(id);
    unsigned char *parsedID =
            reinterpret_cast<unsigned char *>(const_cast<char *>(parsedStrID.c_str()));

    P11IsNonNegative::callChecked(lib::LibP11::P11_PKCS11_store_public_key,
                                  token,
                                  pk,
                                  const_cast<char *>(label.c_str()),
                                  parsedID,
                                  parsedStrID.size());
}

void _PKCS11_generate_key(PKCS11_TOKEN *token,
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
                                  token,
                                  0 /* Currently, algorithm is ignored by LibP11. */,
                                  bits,
                                  const_cast<char *>(label.c_str()),
                                  parsedID,
                                  parsedStrID.size());
}

}  // namespace p11
}  // namespace mococrw
