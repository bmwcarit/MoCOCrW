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
#include <mococrw/key.h>
#include <iostream>

using namespace mococrw;

AsymmetricKeypair createRsaKey(uint keySize, const std::string &password)
{
    RSASpec spec(keySize);
    AsymmetricKeypair key(nullptr);
    try {
        key = AsymmetricKeypair::generate(spec);
    } catch (const openssl::OpenSSLException &e) {
        std::cerr << "Failure generating RSA key." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }

    /* optional: encrypt the key while exporting to PEM */
    auto pem = key.privateKeyToPem(password);
    std::cout << "Encrypted RSA key: " << std::endl << pem << std::endl;

    return key;
}

AsymmetricKeypair createEccKey(openssl::ellipticCurveNid curve, const std::string &password)
{
    ECCSpec spec(curve);
    AsymmetricKeypair key(nullptr);
    try {
        key = AsymmetricKeypair::generate(spec);
    } catch (const MoCOCrWException &e) {
        std::cerr << "Failure generating key." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }

    /* optional: encrypt the key while exporting to PEM */
    auto pem = key.privateKeyToPem(password);
    std::cout << "Encrypted ECC key: " << std::endl << pem << std::endl;

    return key;
}

void exportPublicKey(const AsymmetricPublicKey &pubKey)
{
    std::cout << "PubKey: " << std::endl << pubKey.publicKeyToPem() << std::endl;
}

int main(void)
{
    auto rsaKeyPair = createRsaKey(2048, "secretPassword");
    /* AsymmetricKeypair is a specialisation of AsymmetricPublicKey so we do an implicit upcast here
     * AsymmetricPrivateKey is the same as AsymmetricKeypair */
    exportPublicKey(rsaKeyPair);

    auto eccKeyPair = createEccKey(openssl::ellipticCurveNid::Ed448, "secretPassword");
    exportPublicKey(eccKeyPair);

    auto eccNistKeyPair = createEccKey(openssl::ellipticCurveNid::SECP_521r1, "secretPassword");
    exportPublicKey(eccKeyPair);

    return 0;
}
