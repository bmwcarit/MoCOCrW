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

/*
 * This is a simple test binary to ensure that libmococrw can be used in an
 * SDK environment that has the library and all the cmake files in place.
 */

#include <iostream>

#include <mococrw/key.h>
#include <mococrw/x509.h>
#include <mococrw/csr.h>

using namespace mococrw;

const std::string certPemString{
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDijCCAnICCQDLbB6fOKuKUjANBgkqhkiG9w0BAQsFADBHMQswCQYDVQQGEwJk\n"
        "ZTELMAkGA1UECAwCYncxDDAKBgNVBAcMA3VsbTEMMAoGA1UECgwDQk1XMQ8wDQYD\n"
        "VQQLDAZDYXIgSVQwHhcNMTcwMzA5MDkxOTI4WhcNMTcxMTIwMDkxOTI4WjCBxjES\n"
        "MBAGA1UEAwwJSW1BVGVhcG90MQswCQYDVQQGEwJERTENMAsGA1UEBwwEb2JlbjEQ\n"
        "MA4GA1UECAwHbmViZW5hbjEWMBQGA1UECwwNTGludXggU3VwcG9ydDEMMAoGA1UE\n"
        "CgwDQk1XMSkwJwYJKoZIhvcNAQkBFhpzdXBwb3J0QGxpbnV4LmJtd2dyb3VwLmNv\n"
        "bTExMC8GA1UEBRMoRUNVLVVJRDowOEUzNkRENTAxOTQxNDMyMzU4QUZFODI1NkJD\n"
        "NkVGRDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL+7+KU8KW3lV9W3\n"
        "keTv2/6nWsVhtOCdsM0q+8Z1ttZ+jh0R2Ki2hqKFfxd91uhSjRunRu7LUvWaDnW0\n"
        "1trNvwyyAPIC33r8JwmBk4y6R0tYrw4JE4fEsQpSyjtsi9OOeG9yJbO9EDSjEgfU\n"
        "H4vjgiBQolnTr5OetNB4doJ+lAIUTU9j8woqVr1Y7hqDoW2S9vs6z658QIseSGqB\n"
        "BG1ZuJkCO+VTjdSETPgQWnWlOl9aS+utyvT/CLH8MvBmkpMV8D8P0adpT6AB3NQY\n"
        "iK6EuFRzGAJtCFWF+iL2pyhEKb0gaM7Bb7UROxo+BVUc5w1WWZWpm9X6F5LGTnLt\n"
        "S9fxZccCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEADu1VAiSfn5DTyymTWIByDJgd\n"
        "F9czFPRqyPL3kK3SpMQDqj8uuTYYbgPWP5PPUp2qzazubSWEK3sgu08pM9F/oBJS\n"
        "XXT/FbrfR38LG+hHer6hqBNmN4+mlifdiNCguqEowouAQfduGfGHzNdrUlt0svIs\n"
        "b4Jv7NXsn4pBx6ObGfYWNlxD1zwt71pdjVdwUQqJIEVihh0Bwv4wSmqFJ/iWJdpY\n"
        "0v1OLbCDbbOXPLx/fWyf0TN3bt/Fr1OlGY4UCnKxi+sjTRzWHcmQ2Ox6DgI9MOMZ\n"
        "o7k8jBD0+ZUfE2t9tXJuTKSldE7TuK9ff3NFc433s3FVNPqSE59qs+pJW5joLA==\n"
        "-----END CERTIFICATE-----\n"};

int main(int, char **)
{

    // Smoke test 1: Generate a CSR
    auto dn = DistinguishedName::Builder()
                      .commonName("ImATeapot")
                      .countryName("DE")
                      .organizationName("Linux AG")
                      .organizationalUnitName("Linux Support")
                      .pkcs9EmailAddress("support@example.com")
                      .localityName("oben")
                      .stateOrProvinceName("nebenan")
                      .serialNumber("08E36DD501941432358AFE8256BC6EFD")
                      .build();
    auto keypair = AsymmetricKeypair::generateRSA();
    CertificateSigningRequest csr{dn, keypair};
    auto pemString = csr.toPem();
    auto publicKey = csr.getPublicKey();
    if (pemString.size() == 0 || publicKey.publicKeyToPem().size() == 0)
    {
        std::cerr << "CSR generation seemed to have failed" << std::endl;
        std::cerr << "CSR output is\n--->\n" << pemString << "\n<---" << std::endl;
        return -1;
    }

    // Smoke test 2: Load a certificate
    auto cert = X509Certificate::fromPEM(certPemString);
    if (cert.internal() == nullptr) {
        std::cerr << "Loading of test certificate failed" << std::endl;
        return -1;
    }

    std::cerr << "Smoke tests successful" << std::endl;
    return 0;
}
