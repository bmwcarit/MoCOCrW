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
#include "rsa_example.h"

#include <mococrw/asymmetric_crypto_ctx.h>

#include "mococrw/private/IOUtils.h"
#include "mococrw/private/parsingUtils.h"

using namespace mococrw;

void parseCommandlineArgs(int argc, char *argv[], po::variables_map &vm)
{


    po::options_description rsa("RSA related arguments for decryption and encryption");
    rsa.add_options()
        ("padding", po::value<std::string>(), "The padding used for RSA en/decryption. Optional. Default: oaep. "
                                              "Available: oaep, no, pkcs. Mask generation function for OAEP "
                                              "is MGF1")
        ("oaep-hash-algo", po::value<std::string>(), "Optional: The hash algorith used for OAEP. Default: SHA256 "
                                                     "Available: SHA256, SHA384, SHA512, SHA3-256, SHA3-384, SHA3-512")
        ("oaep-label", po::value<std::string>()->default_value(""), "RSA OAEP: optional label to be associated with the "
                                                                    "message. The default value, if not provided, is "
                                                                    "the empty string")
    ;

    po::options_description cmdlineOptions;
    cmdlineOptions.add(get_generic_options_description())
                   .add(get_encryption_options_description())
                   .add(get_common_asymmetric_options_description())
                   .add(rsa);

    succeedOrExit(!parseCommandLineOptions(cmdlineOptions, vm, argc, argv), "Failure parsing command line.");

    if (vm.count("help") || argc == 1) {
        std::cerr << cmdlineOptions << "\n";
        exit(EXIT_SUCCESS);
    }

    succeedOrExit(!isEncryptionOptionsValid(vm), "");
    succeedOrExit(!isGetCommonAsymmetricOptionsValid(vm), "You need to specify a private key for encryption or a "
                                                          "cert/public key for decryption");

    succeedOrExit(vm.count("oaep-hash-algo") && !vm.count("padding"), "Use --oaep-hash-algo in conjuction with "
                                                                      "--padding oaep");
    succeedOrExit(vm.count("padding") && vm.count("oaep-hash-algo") && vm["padding"].as<std::string>().compare("oaep"),
            "Use --oaep-hash-algo only with --padding oaep");

    succeedOrExit(!vm.count("data"), "You need to specify some data for en-/decryption. "
                                     "For encryption you can also use an empty string ");
}

std::shared_ptr<RSAEncryptionPadding> getPadding(const po::variables_map &vm)
{
    if (!vm.count("padding")) {
        /* Default is OAEP padding */
        return std::make_shared<OAEPPadding>();
    }

    std::string paddingString = vm["padding"].as<std::string>();
    if (!paddingString.compare("oaep")) {
        if (vm.count("oaep-hash-algo")) {
            auto digest = getDigestType(vm["oaep-hash-algo"].as<std::string>());
            succeedOrExit(digest == openssl::DigestTypes::NONE, "Unsupported digest ("
                          << vm["oaep-hash-algo"].as<std::string>() << ") is selected for OAEP!");
            // As we only support one MGF (MGF1) we use the nullptr here, which then instantiates MGF1 as MGF
            return std::make_shared<OAEPPadding>(digest, nullptr, vm["oaep-label"].as<std::string>());
        }
        return std::make_shared<OAEPPadding>();
    } else if (!paddingString.compare("pkcs")) {
        return std::make_shared<PKCSPadding>();
    } else if (!paddingString.compare("no")) {
        return std::make_shared<NoPadding>();
    }

    std::cerr << "Please select a supported Padding scheme. " << paddingString << " is invalid." << std::endl;
    exit(EXIT_FAILURE);
}

void parseCommonData(struct RsaData &rsaData, std::shared_ptr<const po::variables_map> vm)
{
    rsaData.padding = getPadding(*vm.get());
    if ((*vm.get()).count("chaining")) {
        rsaData.chaining = true;
    }
    try {
        rsaData.data = utility::fromHex((*vm.get())["data"].as<std::string>());
    } catch (MoCOCrWException &e) {
        std::cerr << "Failure in crypto engine: ";
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    rsaData.vm = vm;
}

void parseDecryptData(struct RsaData &rsaData, std::shared_ptr<const po::variables_map> vm)
{
    parseCommonData(rsaData, vm);
    rsaData.privKey = std::make_shared<AsymmetricPrivateKey>(
                loadPrivkeyFromFile((*vm.get())["private-key"].as<std::string>(),
                (*vm.get())["private-key-password"].as<std::string>()));
}

void parseEncryptData(struct RsaData &rsaData, std::shared_ptr<const po::variables_map> vm)
{
    parseCommonData(rsaData, vm);
    rsaData.pubKey = std::make_shared<AsymmetricPublicKey>(
                loadPubkeyFromFile((*vm.get())["public-key"].as<std::string>()));
}

int main(int argc, char *argv[])
{
    auto vm = std::make_shared<po::variables_map>();
    struct RsaData rsaData;
    parseCommandlineArgs(argc, argv, *vm.get());

    try {
        if (vm->count("decrypt")) {
            parseDecryptData(rsaData, vm);
            decrypt_rsa(rsaData);
        } else {
            parseEncryptData(rsaData, vm);
            encrypt_rsa(rsaData);
        }
    }  catch (boost::wrapexcept<boost::program_options::invalid_command_line_syntax> &e) {
        std::cerr << "Failure parsing the input. Please check your input!" << std::endl << "Failure: ";
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    return 0;
}
