/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#pragma once

#include <chrono>

#include "openssl_wrap.h"

namespace mococrw
{

/**
 * This class contains additional information that is used when a certificate is signed.
 * An example would be the duration until the certificate expires.
 */
class CertificateSigningParameters
{
public:
    /// A builder class for signing parameters.
    class Builder;

    /**
     * @return the duration how long a signed certificate should be valid.
     */
    const std::chrono::system_clock::duration& certificateValidity() const
    {
        return _certificateValidity;
    }

    /**
     * @return the digest type used for signing certificates.
     */
    openssl::DigestTypes digestType() const
    {
        return _digestType;
    }

    bool operator==(const CertificateSigningParameters &other) const
    {
        return _certificateValidity == other._certificateValidity
                && _digestType == other._digestType;
    }

private:
    std::chrono::system_clock::duration _certificateValidity;
    openssl::DigestTypes _digestType;
};

class CertificateSigningParameters::Builder
{
public:
    template<class T>
    Builder& certificateValidity(T&& validity)
    {
        _sp._certificateValidity = std::forward<T>(validity);
        return *this;
    }

    template<class T>
    Builder& digestType(T&& type)
    {
        _sp._digestType = std::forward<T>(type);
        return *this;
    }

    inline CertificateSigningParameters build()
    {
        return _sp;
    }

private:
    CertificateSigningParameters _sp;
};

} //::mococrw
