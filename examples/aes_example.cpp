#include <iostream>
#include <unordered_map>
#include <string>

#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

#include <mococrw/symmetric_crypto.h>
#include <mococrw/x509.h>

#include "common.h"
#include "IOUtils.h"
#include "parsingUtils.h"

namespace po = boost::program_options;
using namespace mococrw;
void parseCommandlineArgs(int argc, char *argv[], po::variables_map &vm)
{
    po::options_description genericAesOptions("Generic options for hash value calculation");
    genericAesOptions.add_options()
        ("key", po::value<std::string>(), "The key which shall be used for encryption/decryption. Two sizes are "
                                          "supported: 128 and 256 bits (16 and 32 bytes)")
        ("operation-mode", po::value<std::string>(), "The operation mode. Supported: GCM, CTR, CBC. GCM is the only "
                                                     "mode supporting Authenticated Encryption (AE)")
        ("padding", po::value<std::string>()->default_value("PKCS"), "The padding mode. Optional. "
                                                                     "Default: PKCS Supported: PKCS, NO")
        ("iv", po::value<std::string>(), "The IV value used for en-/decryption in hex form (with or without 0x "
                                         "prepended). If empty a random value is used. Default: empty")
    ;
    po::options_description aesAuthenticatedOptions("Generic options for hash value calculation");
    aesAuthenticatedOptions.add_options()
        ("auth-data", po::value<std::string>(), "Authentication data in hex form (with or without 0x "
                                              "prepended). Optional. Can only be used in conjunction with GCM mode.")
        ("auth-tag", po::value<std::string>(), "Authentication tag in hex form (with or without 0x prepended). "
                                               "Mandatory for decryption")
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

    try {
        po::store(po::parse_command_line(argc, argv, cmdlineOptions), vm);
    }  catch (boost::wrapexcept<boost::program_options::invalid_command_line_syntax> &e) {
        std::cerr << "Failure parsing the input. Please check your input!" << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    } catch (boost::wrapexcept<boost::program_options::invalid_option_value> &e) {
        std::cerr << "Got invalid option value (e.g. string for integer). Please check your input!" << std::endl;
        exit(EXIT_FAILURE);
    } catch (boost::wrapexcept<boost::program_options::unknown_option> &e) {
        std::cerr << "Unknown option selected: ";
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    po::notify(vm);

    if (vm.count("help") || argc == 1) {
        std::cerr << cmdlineOptions << "\n";
        exit(EXIT_SUCCESS);
    }

    succeedOrExit(!isEncryptionOptionsValid(vm), "You can either decrypt or encrypt the data");
    succeedOrExit(!vm.count("data"), "You need to specify data which shall be en- or decrypted");
    succeedOrExit(!vm.count("key"), "You need to provide a key for en-/decryption");
    succeedOrExit(!vm.count("operation-mode"), "You need to specify an operation mode");

    auto opMode = boost::to_upper_copy<std::string>(vm["operation-mode"].as<std::string>());
    succeedOrExit(opMode.compare("GCM") && vm.count("auth-data"), "Authentication data is specified but "
                                                                             "GCM is not selected.");
    auto keySize = utility::fromHex(vm["key"].as<std::string>()).size();
    succeedOrExit(keySize != 16 && keySize != 32, "The given key size is not supported. Key size: " << keySize);

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

void aesEncrypt(const po::variables_map &vm)
{

    auto secretKey = utility::fromHex(vm["key"].as<std::string>());
    auto operationMode = getOperationMode(vm);
    auto plaintext = utility::fromHex(vm["data"].as<std::string>());

    auto encryptorBuilder = AESCipherBuilder{operationMode, secretKey.size() == 32 ?
                SymmetricCipherKeySize::S_256 : SymmetricCipherKeySize::S_128, secretKey};
    encryptorBuilder.setPadding(getPadding(vm));
    if (vm.count("iv")) {
        encryptorBuilder.setIV(utility::fromHex(vm["iv"].as<std::string>()));
    }

    std::shared_ptr<SymmetricCipherI> encryptor;
    AuthenticatedEncryptionI *authenticatedEncryptor = nullptr;
    if (isAuthenticatedCipherMode(operationMode)) {
        if (vm.count("auth-tag-length")) {
            encryptorBuilder.setAuthTagLength(vm["auth-tag-length"].as<size_t>());
        }
        encryptor = encryptorBuilder.buildAuthenticatedEncryptor();

        // NOTE: In a real code you usually know type of the encryption in advance and hardly need
        // to cast. Here we do this to keep tests compact and improve on code reuse.
        authenticatedEncryptor = dynamic_cast<AuthenticatedEncryptionI*>(encryptor.get());
        if (vm.count("auth-data")) {
            authenticatedEncryptor->addAssociatedData(utility::fromHex(vm["auth-data"].as<std::string>()));
        }
    }
    else {
        encryptor = encryptorBuilder.buildEncryptor();
    }

    encryptor->update(plaintext);
    auto ciphertext = encryptor->finish();
    auto iv = encryptor->getIV();

    std::vector<uint8_t> tag;

    if (vm.count("chaining")) {
        std::cout << "--operation-mode " << vm["operation-mode"].as<std::string>() << " ";
        std::cout << "--iv " << utility::toHex(iv) << " ";
        std::cout << "--data " << utility::toHex(ciphertext) << " ";
        std::cout << "--padding " << vm["padding"].as<std::string>() << " ";
        if (authenticatedEncryptor) {
            std::cout << "--auth-tag " << utility::toHex(authenticatedEncryptor->getAuthTag()) << " ";
            if (vm.count("auth-tag-length")) {
                std::cout << "--auth-tag-length " << vm["auth-tag-length"].as<size_t>() << " ";
            }
            if (vm.count("auth-data")) {
                std::cout << "--auth-data " << vm["auth-data"].as<std::string>();
            }
        }
        std::cout << std::endl;
        return;
    }

    std::cout << "Ciphertext: " << utility::toHex(ciphertext) << std::endl;
    std::cout << "IV: " << utility::toHex(iv) << std::endl;

    if (authenticatedEncryptor) {
        std::cout << "Authentication Tag: " << utility::toHex(authenticatedEncryptor->getAuthTag()) << std::endl;
    }
}

void aesDecrypt(const po::variables_map &vm)
{
    auto secretKey = utility::fromHex(vm["key"].as<std::string>());
    auto operationMode = getOperationMode(vm);
    auto ciphertext = utility::fromHex(vm["data"].as<std::string>());
    auto iv = utility::fromHex(vm["iv"].as<std::string>());

    auto decryptorBuilder = AESCipherBuilder{operationMode, secretKey.size() == 32 ?
                SymmetricCipherKeySize::S_256 : SymmetricCipherKeySize::S_128, secretKey}.setIV(iv);
    decryptorBuilder.setPadding(getPadding(vm));

    std::shared_ptr<SymmetricCipherI> decryptor;
    AuthenticatedEncryptionI *authenticatedDecryptor = nullptr;
    if (isAuthenticatedCipherMode(operationMode)) {
        decryptor = decryptorBuilder.buildAuthenticatedDecryptor();

        // NOTE: In a real code you usually know type of the encryption in advance and hardly need
        // to cast. Here we do this to keep tests compact and improve on code reuse.
        authenticatedDecryptor = dynamic_cast<AuthenticatedEncryptionI*>(decryptor.get());
        if (vm.count("auth-data")) {
            authenticatedDecryptor->addAssociatedData(utility::fromHex(vm["auth-data"].as<std::string>()));
        }
    }
    else {
        decryptor = decryptorBuilder.buildDecryptor();
    }

    if (authenticatedDecryptor) {
        authenticatedDecryptor->setAuthTag(utility::fromHex(vm["auth-tag"].as<std::string>()));
    }

    decryptor->update(ciphertext);
    try {
        std::cout << utility::toHex(decryptor->finish()) << std::endl;
    }  catch (MoCOCrWException &e) {
        std::cout << "Decryption failed!" << std::endl;
        std::cout << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{
    po::variables_map vm;
    parseCommandlineArgs(argc, argv, vm);

    if (vm.count("encrypt")) {
        aesEncrypt(vm);
    } else {
        aesDecrypt(vm);
    }

    return 0;
}
