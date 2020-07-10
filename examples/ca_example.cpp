/*
 * #%L
 * %%
 * Copyright (C) 2020 BMW Car IT GmbH
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
#include "ca_example.h"
#include <iostream>

std::shared_ptr<CertificateAuthority> getCa(const struct CaData &caData)
{
    return std::make_shared<CertificateAuthority>(
                *caData.signParams,
                1,
                *caData.rootCert.get(),
                *caData.privKey.get());
}

std::shared_ptr<X509Certificate> createRootCertificate(const struct CaData &caData)
{
    auto rootCert = CertificateAuthority::createRootCertificate(
            *caData.privKey.get(),
            *caData.certDetails,
            0,
            *caData.signParams);

    return std::make_shared<X509Certificate>(std::move(rootCert));
}

std::shared_ptr<X509Certificate> signCsr(const struct CaData &caData)
{
    std::shared_ptr<X509Certificate> cert;
    auto ca = getCa(caData);
    try {
        cert = std::make_shared<X509Certificate>(ca->signCSR(*caData.csr.get()));
    }  catch (openssl::OpenSSLException &e) {
        std::cerr << "Error reading CSR in PEM format. Please validate  your CSR." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    } catch (MoCOCrWException &e) {
        std::cerr << "Failed to create certificate." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
    return cert;
}

