#include <iostream>
#include <stdio.h>

#include <boost/program_options.hpp>
#include <mococrw/asymmetric_crypto_ctx.h>

#include "common.h"
#include "IOUtils.h"
#include "parsingUtils.h"

namespace po = boost::program_options;
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

    try {
        po::store(po::parse_command_line(argc, argv, cmdlineOptions), vm);
    }  catch (boost::wrapexcept<boost::program_options::invalid_command_line_syntax> &e) {
        std::cerr << "Failure parsing the input. Please check your input!" << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
    po::notify(vm);

    if (vm.count("help") || argc == 1) {
        std::cerr << cmdlineOptions << "\n";
        exit(EXIT_SUCCESS);
    }

    succeedOrExit(!(vm.count("decrypt") xor vm.count("encrypt")), "You can either decrypt or encrypt the data");

    if (vm.count("decrypt")) {
        succeedOrExit(!vm.count("private-key"), "You need a private key for decryption.");
    } else {
        succeedOrExit(!(vm.count("public-key") xor vm.count("cert")),
                      "You need a public key or a certificate for encryption");    }

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
            auto digest = getDigest(vm["oaep-hash-algo"].as<std::string>());
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

void printChainingData(const po::variables_map &vm)
{
    if (vm.count("padding")) {
        std::cout << "--padding " << vm["padding"].as<std::string>() << " ";
    }

    if (vm.count("oaep-hash-algo")) {
        std::cout << "--oaep-hash-algo " << vm["oaep-hash-algo"].as<std::string>() << " ";
    }

    if (vm.count("oaep-label")) {
        std::cout << "--oaep-label " << vm["oaep-label"].as<std::string>() << " ";
    }

    std::cout << "--data ";
}

void encrypt_rsa(const po::variables_map &vm) {
    printVerbose("Encrypting using RSA");
    auto pubKey = loadPubkeyFromFile(vm["public-key"].as<std::string>());
    auto padding = getPadding(vm);
    RSAEncryptionPublicKeyCtx rsaPubCtx(pubKey, padding);

    auto ciphertext = rsaPubCtx.encrypt(utility::fromHex(vm["data"].as<std::string>()));

    if (vm.count("chaining")) {
        printChainingData(vm);
    } else {
        printVerbose("Ciphertext: ");
    }
    std::cout << utility::toHex(ciphertext) << std::endl;
}

void decrypt_rsa(const po::variables_map &vm) {
    printVerbose("Decrypting usingRSA");
    auto privKey = loadPrivkeyFromFile(vm["private-key"].as<std::string>(),
                vm["private-key-password"].as<std::string>());
    auto padding = getPadding(vm);
    RSAEncryptionPrivateKeyCtx rsaPrivCtx(privKey, padding);

    auto plaintext = rsaPrivCtx.decrypt(utility::fromHex(vm["data"].as<std::string>()));

    printVerbose("Plaintext: ");
    std::cout << utility::toHex(plaintext) << std::endl;
}

int main(int argc, char *argv[])
{
    po::variables_map vm;
    parseCommandlineArgs(argc, argv, vm);

    try {
        if (vm.count("decrypt")) {
            decrypt_rsa(vm);
        } else {
            encrypt_rsa(vm);
        }
    }  catch (boost::wrapexcept<boost::program_options::invalid_command_line_syntax> &e) {
        std::cerr << "Failure parsing the input. Please check your input!" << std::endl << "Failure: ";
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    } catch (mococrw::MoCOCrWException &e) {
        std::cerr << "Failure in crypto engine: ";
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    return 0;
}
