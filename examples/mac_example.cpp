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
#include <mococrw/mac.h>
#include <mococrw/util.h>
#include <iostream>

#include "mac_example.h"

using namespace mococrw;

std::unique_ptr<mococrw::HMAC> doHmac(const struct MacData &macData)
{
    auto hmac =  std::make_unique<mococrw::HMAC>(macData.digestType, macData.key);
    hmac->update(macData.message);
    return hmac;
}

void verify(const struct MacData &macData)
{
    auto hmac = doHmac(macData);
    auto tag = hmac->finish();

    try {
        hmac->verify(macData.authenticationTag);
    }  catch (MoCOCrWException &e) {
        std::cerr << "Verification failed." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }

    std::cout << "Verification successful." << std::endl;

}

void calculate(const struct MacData &macData)
{
    auto hmac = doHmac(macData);
    auto tag = hmac->finish();

    if (macData.chaining) {
        auto vm = *macData.vm.get();
        std::cout << "--hash-algo " << vm["hash-algo"].as<std::string>() << " ";
        std::cout << "--key " << vm["key"].as<std::string>() << " ";
        std::cout << "--message "<< vm["message"].as<std::string>() << " ";
        std::cout << "--authentication-tag ";
    }
    std::cout << utility::toHex(tag) << std::endl;
}
