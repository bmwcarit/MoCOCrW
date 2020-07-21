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
#include "common.h"
#include "mococrw/private/parsingUtils.h"
#include "mac_example.h"

using namespace mococrw;

void parseCommandlineArgs(int argc, char *argv[], po::variables_map &vm)
{
    po::options_description genericKdfOptions("Generic options for message authentication code. "
                                              "Only HMAC is supported.");
    genericKdfOptions.add_options()
            ("message", po::value<std::string>(), "The message in hex form (with or without 0x "
                                                   "prepended) which shall be used.")
            ("verify", "Verifies the authenticity of a message. An authentication tag is required.")
            ("authentication-tag", po::value<std::string>(), "The authentication tag in hex form (with or without 0x "
                                                             "prepended) which shall be used "
                                                             "for verification")
            ("calculate", "Calculate the message authentication tag using the given arguments.")
            ("chaining", "Print results in a form that they can be used as command line arguments for "
                         "decryption/verification. Optional.")
            ;

    po::options_description hmacOptions("Options for HMAC");
    hmacOptions.add_options()
            ("key", po::value<std::string>(), "The key in hex form (with or without 0x "
                                               "prepended) used MAC.")
            ("hash-algo", po::value<std::string>()->default_value("SHA256"),
                "The hash algorith used for message authentication code calculation. "
                "Default: SHA-256. Available: SHA256, SHA384, SHA512, SHA3-256, SHA3-384, SHA3-512")

            ;

    po::options_description cmdlineOptions;
    cmdlineOptions.add(get_generic_options_description())
            .add(genericKdfOptions)
            .add(hmacOptions)
            ;

    succeedOrExit(!parseCommandLineOptions(cmdlineOptions, vm, argc, argv), "Failure parsing command line.");

    if (vm.count("help") || argc == 1) {
        std::cerr << cmdlineOptions << "\n";
        exit(EXIT_SUCCESS);
    }

    succeedOrExit(!(vm.count("verify") xor vm.count("calculate")), "Select either --calculate or --verify");

    if (vm.count("verify")) {
        succeedOrExit(!vm.count("authentication-tag"), "Please specify the tag (--authentication-tag)");
    }

    succeedOrExit(!vm.count("message"), "Please specify a message (--message)");
    succeedOrExit(!vm.count("key"), "Please specify a key (--key");
}

void parseMacData(struct MacData &macData)
{
    auto vm = *macData.vm.get();
    try {
        macData.message = utility::fromHex(vm["message"].as<std::string>());
        macData.key = utility::fromHex(vm["key"].as<std::string>());
    }  catch (MoCOCrWException &e) {
        std::cerr << "Failed to convert hex value for message or key. Please check your input." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
        macData.digestType = getDigestType(vm["hash-algo"].as<std::string>());
    if (macData.digestType == DigestTypes::NONE) {
        std::cerr << "Failure parsing digest Type: " << vm["hash-algo"].as<std::string>() << std::endl;
        exit(EXIT_FAILURE);
    }

    if (vm.count("verify")) {
        macData.verify = true;
        try {
            macData.authenticationTag = utility::fromHex(vm["authentication-tag"].as<std::string>());
        }  catch (MoCOCrWException &e) {
            std::cerr << "Failed to convert hex value for authenticationTag. Please check your input." << std::endl;
            std::cerr << e.what() << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    if (vm.count("chaining")) {
        macData.chaining = true;
    }
}

int main(int argc, char *argv[])
{
    auto vm = std::make_shared<po::variables_map>();
    parseCommandlineArgs(argc, argv, *vm.get());
    MacData macData(vm);
    parseMacData(macData);

    if (macData.verify) {
        verify(macData);
    } else {
        calculate(macData);
    }

    return 0;
}
