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

#include "mococrw/private/parsingUtils.h"
#include "kdf_example.h"
#include "common.h"

using namespace mococrw;

void parseCommandlineArgs(int argc, char *argv[], po::variables_map &vm)
{
    po::options_description genericKdfOptions("Generic options for key generation.");
    genericKdfOptions.add_options()
            ("password", po::value<std::string>(), "The password/secret key in hex form (with or without 0x "
                                                   "prepended) which shall be used for key derivation.")
            ("output-length", po::value<size_t>(), "The output length in bytes.")
            ("salt", po::value<std::string>()->default_value(""),
             "The salt in hex form (with or without 0x prepended) used for key derivation. Optional. Default: empty")
            ("hash-algo", po::value<std::string>()->default_value("SHA256"),
                "The hash algorithm used for key derivation calculation for PBKDF2 and X963KDF."
                " Default: SHA-256. Available: SHA256, SHA384, SHA512, SHA3-256, SHA3-384, SHA3-512")
            ;

    po::options_description pbkdf2Options("Options for PBKDF2");
    pbkdf2Options.add_options()
            ("pbkdf2", "Use PBKDF2 for key derivation")
            ("iterations", po::value<uint32_t>(), "Number of iterations")
            ;

    po::options_description x963kdfOptions("Options for X963KDF");
    x963kdfOptions.add_options()
            ("x963kdf", "Use X963KDF for key derivation")
            ;

    po::options_description cmdlineOptions;
    cmdlineOptions.add(get_generic_options_description())
            .add(genericKdfOptions)
            .add(pbkdf2Options)
            .add(x963kdfOptions)
            ;

    succeedOrExit(!parseCommandLineOptions(cmdlineOptions, vm, argc, argv), "Failure parsing command line.");

    if (vm.count("help") || argc == 1) {
        std::cerr << cmdlineOptions << "\n";
        exit(EXIT_SUCCESS);
    }

    succeedOrExit(!(vm.count("pbkdf2") xor vm.count("x963kdf")), "Select either --pbkdf2 or --x963kdf");

    if (vm.count("pbkdf2")) {
        succeedOrExit(!vm.count("iterations"), "Please specify the number of iterations");
    }

    succeedOrExit(!vm.count("password"), "Please specify a secret for key derivation (--password)");
    succeedOrExit(!vm.count("output-length"), "Please specify a output length in bytes (--output-length");
}

void getDefaultParams(struct KdfData &kdfData)
{
    auto vm = *kdfData.vm.get();
    try {
        kdfData.password = utility::fromHex(vm["password"].as<std::string>());
        kdfData.salt = utility::fromHex(vm["salt"].as<std::string>());
    }  catch (MoCOCrWException &e) {
        std::cerr << "Failed to convert hex value for password or salt. Please check your input." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
    kdfData.outputLength = vm["output-length"].as<size_t>();
    kdfData.digestType = getDigestType(vm["hash-algo"].as<std::string>());
    if (kdfData.digestType == DigestTypes::NONE) {
        std::cerr << "Failure parsing digest Type: " << vm["hash-algo"].as<std::string>() << std::endl;
        exit(EXIT_FAILURE);
    }

    kdfData.digestType = getDigestType(vm["hash-algo"].as<std::string>());
    if (kdfData.digestType == DigestTypes::NONE) {
        std::cerr << "Failure parsing digest Type: " << vm["hash-algo"].as<std::string>() << std::endl;
        exit(EXIT_FAILURE);
    }
}

void parsePbKdf2Data(struct KdfData &kdfData)
{
    auto vm = *kdfData.vm;
    getDefaultParams(kdfData);
    kdfData.iterations = vm["iterations"].as<uint32_t>();
}

void parseX963kdfData(struct KdfData &kdfData)
{
    getDefaultParams(kdfData);
}

int main(int argc, char *argv[])
{
    auto vm = std::make_shared<po::variables_map>();
    parseCommandlineArgs(argc, argv, *vm.get());
    KdfData kdfData(vm);

    if ((*vm).count("pbkdf2")) {
        parsePbKdf2Data(kdfData);
        pbkdf2(kdfData);
    } else {
        parseX963kdfData(kdfData);
        x963kdf(kdfData);
    }
    return 0;
}
