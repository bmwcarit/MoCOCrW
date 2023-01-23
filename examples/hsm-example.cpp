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
#include <mococrw/hsm.h>
#include <mococrw/key.h>

/* This example demonstrates how to create a PKCS11 engine object,
 * and store/load a key inside the HSM.
 */

using namespace mococrw;

int main(void)
{
    // Information for engine loading and key management.
    std::string id("pkcs11");
    std::string modulePath("/usr/lib/softhsm/libsofthsm2.so");
    std::string tokenLabel("token-label");
    // Don't hardcode the pin in your application, this is just for demonstration purposes
    std::string pin("1234");
    HsmEngine hsmEngine(id, modulePath, tokenLabel, pin);

    /************** ECC key generation **************/
    std::vector<uint8_t> keyIDECC{};
    std::string keyLabelECC("ecc-key-label");
    ECCSpec ecspec;
    // Keypair containing private and public key
    auto eccPrivKey = AsymmetricKeypair::generateKeyOnHSM(hsmEngine, ecspec, keyLabelECC, keyIDECC);

    // Public key can be loaded explicitly
    auto pubKeyEcc = AsymmetricPublicKey::readPublicKeyFromHSM(hsmEngine, keyLabelECC, keyIDECC);

    /************** RSA key generation **************/
    std::vector<uint8_t> keyIDRSA{0x12, 0x34};
    std::string keyLabelRSA{"rsa-key-label"};
    mococrw::RSASpec rsaSpec;
    // AsymmetricPrivateKey is an alias for AsymmetricKeypair so it can be used as well
    auto rsaPrivKey =
            AsymmetricPrivateKey::generateKeyOnHSM(hsmEngine, rsaSpec, keyLabelRSA, keyIDRSA);

    // Private key can also be loaded explicitly
    auto privKeyRsa = AsymmetricPrivateKey::readPrivateKeyFromHSM(hsmEngine, keyLabelRSA, keyIDRSA);

    /**
     * These keys are of types AsymmetricPrivateKey and AsymmetricPublicKey and as such can
     * be used in various cryptographic algorithms where asymmetric cryptography is involved.
     * See ecies-example.cpp, sig-example.cpp, rsa-example.cpp ...
     */

    return 0;
}
