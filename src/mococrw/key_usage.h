/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#pragma once

#include "extension.h"
#include "openssl_wrap.h"

namespace mococrw
{

/**
 * This extension specifies the allowed usages for a key.
 */
class KeyUsageExtension final : public ExtensionBase
{
public:
    class Builder;

    static constexpr openssl::X509Extension_NID NID = openssl::X509Extension_NID::KeyUsage;

    /**
     * @return true if the key may be used for encrypting data in a key exchange.
     * Requires keyAgreement to be set.
     */
    bool decipherOnly() const
    {
        return _decipherOnly;
    }

    /**
     * @return true if the key may be used for decrypting data in a key exchange.
     * Requires keyAgreement to be set.
     */
    bool encipherOnly() const
    {
        return _encipherOnly;
    }

    /**
     * @return true if the key can be used for verifying CRLs.
     */
    bool cRLSign() const
    {
        return _cRLSign;
    }

    /**
     * @return true if the key can be used for verifying certificates.
     */
    bool keyCertSign() const
    {
        return _keyCertSign;
    }

    /**
     * @return true if the key can be used for a key exchange.
     */
    bool keyAgreement() const
    {
        return _keyAgreement;
    }

    /**
     * @return true if the key may be used for encrypting normal data (excluding keys).
     */
    bool dataEncipherment() const
    {
        return _dataEncipherment;
    }

    /**
     * @return true if the key may be used for encrypting keys.
     */
    bool keyEncipherment() const
    {
        return _keyEncipherment;
    }

    /**
     * @return true if the certificate owner may not repudiate certificate actions later on.
     */
    bool nonRepudiation() const
    {
        return _nonRepudiation;
    }

    /**
     * @return true if the key may be used for validating signatures.
     */
    bool digitalSignature() const
    {
        return _digitalSignature;
    }

    openssl::X509Extension_NID getNid() const override
    {
        return NID;
    }

private:
    auto _makeTuple() const
    {
        return std::tie(_decipherOnly, _encipherOnly, _cRLSign, _keyCertSign, _keyAgreement,
                               _dataEncipherment, _keyEncipherment, _nonRepudiation,
                               _digitalSignature);
    }

public:
    bool operator==(const KeyUsageExtension& other) const
    {
        return _makeTuple() == other._makeTuple();
    }

    bool operator!=(const KeyUsageExtension& other) const
    {
        return !operator ==(other);
    }

    std::string getConfigurationString() const override
    {
        std::string string = "critical";
        if (_decipherOnly) {
            string += ",decipherOnly";
        }
        if (_encipherOnly) {
            string += ",encipherOnly";
        }
        if (_cRLSign) {
            string += ",cRLSign";
        }
        if (_keyCertSign) {
            string += ",keyCertSign";
        }
        if (_keyAgreement) {
            string += ",keyAgreement";
        }
        if (_dataEncipherment) {
            string += ",dataEncipherment";
        }
        if (_keyEncipherment) {
            string += ",keyEncipherment";
        }
        if (_nonRepudiation) {
            string += ",nonRepudiation";
        }
        if (_digitalSignature) {
            string += ",digitalSignature";
        }
        return string;
    }

private:
    bool _decipherOnly;
    bool _encipherOnly;
    bool _cRLSign;
    bool _keyCertSign;
    bool _keyAgreement;
    bool _dataEncipherment;
    bool _keyEncipherment;
    bool _nonRepudiation;
    bool _digitalSignature;
};

class KeyUsageExtension::Builder
{
public:
    Builder& decipherOnly()
    {
        _ku._decipherOnly = true;
        return *this;
    }

    Builder& encipherOnly()
    {
        _ku._encipherOnly = true;
        return *this;
    }

    Builder& cRLSign()
    {
        _ku._cRLSign = true;
        return *this;
    }

    Builder& keyCertSign()
    {
        _ku._keyCertSign = true;
        return *this;
    }

    Builder& keyAgreement()
    {
        _ku._keyAgreement = true;
        return *this;
    }

    Builder& dataEncipherment()
    {
        _ku._dataEncipherment = true;
        return *this;
    }

    Builder& keyEncipherment()
    {
        _ku._keyEncipherment = true;
        return *this;
    }

    Builder& nonRepudiation()
    {
        _ku._nonRepudiation = true;
        return *this;
    }

    Builder& digitalSignature()
    {
        _ku._digitalSignature = true;
        return *this;
    }

    inline KeyUsageExtension build()
    {
        return _ku;
    }

private:
    KeyUsageExtension _ku;
};

} //::mococrw
