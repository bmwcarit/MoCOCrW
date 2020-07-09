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
#include "aes_example.h"
#include "mococrw/private/IOUtils.h"
#include "mococrw/private/parsingUtils.h"

namespace po = boost::program_options;
using namespace mococrw;

void parseCommandlineArgs(int argc, char *argv[], po::variables_map &vm)
{
    po::options_description genericAesOptions("Options for symmetric en-/decryption");
    genericAesOptions.add_options()
        ("key", po::value<std::string>(), "The key which shall be used for encryption/decryption in hex form (with or "
                                          "without 0x prepended). Two sizes are supported: 128 and 256 bits (16 and 32 "
                                          "bytes).")
        ("operation-mode", po::value<std::string>(), "The operation mode. Supported: GCM, CTR, CBC. GCM is the only "
                                                     "mode supporting Authenticated Encryption (AE)")
        ("padding", po::value<std::string>()->default_value("PKCS"), "The padding mode. Optional. "
                                                                     "Default: PKCS Supported: PKCS, NO")
        ("iv", po::value<std::string>(), "The IV value used for en-/decryption in hex form (with or without 0x "
                                         "prepended). If empty a random value is used for encryption. Default: empty. "
                                         "This value is mandatory for decrpytion.")
    ;
    po::options_description aesAuthenticatedOptions("Options for authenticated encryption (AE)");
    aesAuthenticatedOptions.add_options()
        ("auth-data", po::value<std::string>(), "Authentication data in hex form (with or without 0x "
                                                "prepended). Optional. Can only be used in conjunction with GCM mode.")
        ("auth-tag", po::value<std::string>(), "Authentication tag in hex form (with or without 0x prepended). "
                                               "Mandatory for authenticated decryption.")
        ("auth-tag-length", po::value<size_t>(),
         "The authentication tag length in bytes.\nUse this method to change default length of authentication tag "
         "which the encryptor will return in getAuthTag(). Default value is 128 bits (16bytes).\nDo not use when "
         "creating a cipher for decryption.\n\nPlease note that security of authenticated encryption directly depends "
         "on the length of the authentication tag. If you think that you have valid reasons for using tag lengths "
         "less than 64bit, please consult with Appendix C of "
         "https://csrc.nist.gov/publications/detail/sp/800-38d/final.")
    ;

    po::options_description cmdlineOptions;
    cmdlineOptions.add(get_generic_options_description())
                  .add(get_encryption_options_description())
                  .add(genericAesOptions)
                  .add(aesAuthenticatedOptions);

    succeedOrExit(!parseCommandLineOptions(cmdlineOptions, vm, argc, argv), "Failure parsing command line.");

    if (vm.count("help") || argc == 1) {
        std::cerr << cmdlineOptions << "\n";
        exit(EXIT_SUCCESS);
    }

    succeedOrExit(!isEncryptionOptionsValid(vm), "");
    succeedOrExit(!vm.count("data"), "You need to specify data which shall be en- or decrypted");
    succeedOrExit(!vm.count("key"), "You need to provide a key for en-/decryption");
    succeedOrExit(!vm.count("operation-mode"), "You need to specify an operation mode");

    auto opMode = boost::to_upper_copy<std::string>(vm["operation-mode"].as<std::string>());
    succeedOrExit(opMode.compare("GCM") && vm.count("auth-data"), "Authentication data is specified but "
                                                                             "GCM is not selected.");
    try {
        auto keySize = utility::fromHex(vm["key"].as<std::string>()).size();
        succeedOrExit(keySize != 16 && keySize != 32, "The given key size is not supported. Key size: " << keySize);
    }  catch (MoCOCrWException &e) {
        std::cerr << "Failure getting key hex string." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    succeedOrExit(vm.count("decrypt") && !vm.count("iv"), "You need to provide an IV for decryption");
    succeedOrExit(vm.count("decrypt") && !opMode.compare("GCM") && !vm.count("auth-tag"),
                  "You need to provide an IV for decryption in GCM mode (authenticated encryption)");

}

SymmetricCipherMode getOperationMode(const po::variables_map &vm)
{
    auto opMode = boost::to_upper_copy<std::string>(vm["operation-mode"].as<std::string>());
    if (!opMode.compare("GCM")) {
        return SymmetricCipherMode::GCM;
    } else if (!opMode.compare("CTR")) {
        return SymmetricCipherMode::CTR;
    } else if (!opMode.compare("CBC")) {
        return SymmetricCipherMode::CBC;
    }

    std::cerr << "Not valid symmetric operation mode is given." << std::endl;
    exit(EXIT_FAILURE);
}

SymmetricCipherPadding getPadding(const po::variables_map &vm)
{
    // The default is set in the options
    std::string paddingString = boost::to_upper_copy<std::string>(vm["padding"].as<std::string>());
    if (!paddingString.compare("PKCS")) {
        return SymmetricCipherPadding::PKCS;
    } else if (!paddingString.compare("NO")) {
        return SymmetricCipherPadding::NO;
    }

    std::cerr << "Please select a supported Padding scheme. " << paddingString << " is invalid." << std::endl;
    exit(EXIT_FAILURE);
}

std::vector<uint8_t> getIv(const po::variables_map &vm)
{
    try {
        return utility::fromHex(vm["iv"].as<std::string>());
    }  catch (MoCOCrWException &e) {
        std::cerr << "Failure getting IV hex string." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

void parseData(struct AesData &aesData)
{
    auto vm = *aesData.vm.get();

    if (vm.count("chaining")) {
        aesData.chaining = true;
    }

    std::vector<uint8_t> secretKey;
    try {
        aesData.secretKey = utility::fromHex(vm["key"].as<std::string>());
    }  catch (MoCOCrWException &e) {
        std::cerr << "Failure getting key hex string." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
    std::vector<uint8_t> data;
    try {
        aesData.data = utility::fromHex(vm["data"].as<std::string>());
    }  catch (MoCOCrWException &e) {
        std::cerr << "Failure getting data hex string." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    aesData.operationMode = getOperationMode(vm);
    aesData.padding = getPadding(vm);

    if (vm.count("iv")) {
        aesData.iv = getIv(vm);
    }

    if (vm.count("auth-tag-length")) {
        aesData.authTagLength = vm["auth-tag-length"].as<size_t>();
    }

    if (vm.count("auth-data")) {
        try {
            aesData.authData = utility::fromHex(vm["auth-data"].as<std::string>());
        }  catch (MoCOCrWException &e) {
            std::cerr << "Failure getting auth data hex string." << std::endl;
            std::cerr << e.what() << std::endl;
            exit(EXIT_FAILURE);
        }
    }
}

void parseEncryption(struct AesData &aesData)
{
    parseData(aesData);
}

void parseDecryption(struct AesData &aesData)
{
    auto vm = *aesData.vm.get();
    parseData(aesData);
    if (vm.count("auth-tag")) {
        try {
            aesData.authTag = utility::fromHex(vm["auth-tag"].as<std::string>());
        } catch (MoCOCrWException &e) {
            std::cerr << "Failure getting auth tag hex string." << std::endl;
            std::cerr << e.what() << std::endl;
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char *argv[])
{
    auto vm = std::make_shared<po::variables_map>();
    parseCommandlineArgs(argc, argv, *vm.get());
    AesData aesData(vm);

    if ((*vm.get()).count("encrypt")) {
        parseEncryption(aesData);
        aesEncrypt(aesData);
    } else {
        parseDecryption(aesData);
        aesDecrypt(aesData);
    }

    return 0;
}

