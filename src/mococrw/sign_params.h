/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#pragma once

#include <chrono>
#include <map>
#include <type_traits>

#include "openssl_wrap.h"

#include "error.h"
#include "extension.h"

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
     * @return the duration how long a signed certificate should be valid, from the starting point.
     */
    const std::chrono::system_clock::duration& certificateValidity() const
    {
        return _certificateValidity;
    }

    /**
     * @return the timestamp from when a signed certificate should be valid. Defaults to now.
     */
    std::chrono::system_clock::time_point notBefore() const
    {
        if (_notBefore.is_initialized()) {
            return _notBefore.get();
        } else {
            // Default start time is now (minus one second)
            return std::chrono::system_clock::now() - std::chrono::seconds(1);
        }
    }

    /**
     * @return the digest type used for signing certificates.
     */
    openssl::DigestTypes digestType() const
    {
        return _digestType;
    }

    const std::map<openssl::X509Extension_NID, std::shared_ptr<ExtensionBase> >&
    extensionMap() const
    {
        return _extensions;
    }

    /**
     * @param nid the NID which the extension that is looked for has
     * @return the extension with the given NID
     * @throw MoCOCrWException if no such extension is present.
     */
    std::shared_ptr<ExtensionBase> extension(openssl::X509Extension_NID nid) const
    {
        auto extension = _extensions.find(nid);

        if (extension == _extensions.end()) {
            throw MoCOCrWException("Extension type was not added to CertificateSigningParameters");
        }

        return extension->second;
    }

    /**
     * @return the extension with the requested extension type, if present.
     * @throw MoCOCrWException if no such extension is present.
     */
    template<class T>
    inline std::shared_ptr<T> extension() const
    {
        static_assert(std::is_base_of<ExtensionBase, T>::value,
                      "Extension is not derived from ExtensionBase");
        return std::dynamic_pointer_cast<T>(extension(T::NID));
    }

private:
    auto  _makeTuple() const
    {
        return std::tie(_certificateValidity, _notBefore, _digestType, _extensions);
    }

public:
    bool operator==(const CertificateSigningParameters &other) const
    {
        return _makeTuple() == other._makeTuple();
    }

    bool operator !=(const CertificateSigningParameters &other) const
    {
        return !operator ==(other);
    }

private:
    boost::optional<std::chrono::system_clock::time_point> _notBefore;
    std::chrono::system_clock::duration _certificateValidity;
    openssl::DigestTypes _digestType;
    //There is no more than one extension of the same type, so every extension type
    //is unique in the extension map.
    std::map<openssl::X509Extension_NID, std::shared_ptr<ExtensionBase> > _extensions;

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
    Builder& notBefore(T&& notBefore)
    {
        _sp._notBefore = std::forward<T>(notBefore);
        return *this;
    }

    template<class T>
    Builder& digestType(T&& type)
    {
        _sp._digestType = std::forward<T>(type);
        return *this;
    }

    template<class T>
    Builder& addExtension(T extension)
    {
        static_assert(std::is_base_of<ExtensionBase, T>::value,
                      "Extension is not derived from ExtensionBase");

        _sp._extensions[extension.getNid()] = std::make_shared<T>(std::move(extension));
        return *this;
    }

    Builder& addExtension(std::shared_ptr<ExtensionBase> extension)
    {
        _sp._extensions[extension->getNid()] = std::move(extension);
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
