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
#include <mococrw/kdf.h>
#include <iostream>

using namespace mococrw;

int main(void)
{
    auto password = utility::fromHex("deadbeef");
    /* Set the desired output length */
    auto outputLength = 256;
    auto salt = utility::fromHex("beefdead");
    auto digestType = DigestTypes::SHA512;
    int iterations = 1024;

    /* PBKDF2 */
    auto pbkdf2 = PBKDF2(digestType, iterations);
    /* OpenSSLException is thrown if an error in OpenSSL happens */
    std::vector<uint8_t> derivedKey = pbkdf2.deriveKey(password, outputLength, salt);
    std::cout << utility::toHex(derivedKey) << std::endl;

    /* X963KDF */
    auto x963kdf = X963KDF(digestType);
    /* OpenSSLException is thrown if an error in OpenSSL happens */
    derivedKey = x963kdf.deriveKey(password, outputLength, salt);
    std::cout << utility::toHex(derivedKey) << std::endl;

    return 0;
}
