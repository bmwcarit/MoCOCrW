/*
 * #%L
 * %%
 * Copyright (C) 2018 BMW Car IT GmbH
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

template<class Res, Res(Func)(const std::string&, const std::string&)>
auto openSSLObjectFromFile(const std::string &filename, const std::string &password)
{
    auto buffer = bytesFromFile<char>(filename);
    return Func({buffer.data(), buffer.size()}, password);
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

mococrw::CertificateRevocationList loadCrlFromFile(const std::string &filename)
{
    return openSSLObjectFromFile<mococrw::CertificateRevocationList,
        mococrw::CertificateRevocationList::fromPEM>(filename);
}

mococrw::AsymmetricPublicKey loadPubkeyFromFile(const std::string &filename)
{
    return openSSLObjectFromFile<mococrw::AsymmetricPublicKey,
        mococrw::AsymmetricPublicKey::readPublicKeyFromPEM>(filename);
}

mococrw::AsymmetricPrivateKey loadPrivkeyFromFile(const std::string &filename, const std::string &password)
{
    return openSSLObjectFromFile<mococrw::AsymmetricPrivateKey,
        mococrw::AsymmetricPrivateKey::readPrivateKeyFromPEM>(filename, password);
}

