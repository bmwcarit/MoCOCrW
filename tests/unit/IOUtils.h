/**
 * @file
 * @copyright (C) 2018, BMW AG
 * @copyright (C) 2018, BMW Car IT GmbH
 */
#pragma once

#include <fstream>

#include "mococrw/x509.h"

template<class T>
std::vector<T> bytesFromFile(const std::string &filename)
{
    static_assert(sizeof(T) == sizeof(char), "bytesFromFile only works with 1 byte data types");

    std::ifstream file{filename};
    if (!file.good()) {
        std::string errorMsg{"Cannot load certificate from file "};
        errorMsg = errorMsg + filename;
        throw std::runtime_error(errorMsg);
    }

    file.seekg(0, std::ios::end);
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<T> buffer;
    buffer.resize(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

template<class Res, Res(Func)(const std::string&)>
auto openSSLObjectFromFile(const std::string &filename)
{
    auto buffer = bytesFromFile<char>(filename);
    return Func({buffer.data(), buffer.size()});
}

mococrw::X509Certificate loadCertFromFile(const std::string &filename)
{
    return openSSLObjectFromFile<mococrw::X509Certificate,
            mococrw::X509Certificate::fromPEM>(filename);
}

mococrw::X509Certificate loadCertFromDERFile(const std::string &filename)
{
    auto buffer = bytesFromFile<uint8_t>(filename);
    return mococrw::X509Certificate::fromDER(buffer);
}

mococrw::AsymmetricPublicKey loadPubkeyFromFile(const std::string &filename)
{
    return openSSLObjectFromFile<mococrw::AsymmetricPublicKey,
        mococrw::AsymmetricPublicKey::readPublicKeyFromPEM>(filename);
}

