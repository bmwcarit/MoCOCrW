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
#include "ecies_example.h"
#include "mococrw/private/IOUtils.h"
#include "mococrw/private/parsingUtils.h"

using namespace mococrw;
namespace po = boost::program_options;

/*
 * Asymmetric encryption using ECIES
 */

void parseCommandlineArgs(int argc, char *argv[], po::variables_map &vm)
{

    po::options_description ecies_decrypt("Additional ECIES decrypt arguments");
    ecies_decrypt.add_options()
        ("eph-key", po::value<std::string>(), "The ephemeral key used during encryption (needed for decryption) "
                                              "in hex form (with or without 0x prepended)")
        ("mac-value", po::value<std::string>(), "The message authentication code calculated during encryption in hex "
                                                "form (with or without 0x prepended, needed for decryption)")
    ;

    po::options_description ecies_optional("ECIES optional arguments");
    ecies_optional.add_options()
        ("mac-algo", po::value<std::string>(), "The Message Authentication Code algorithm (optional. "
                                               "default: HMAC. Available: HMAC)")
        ("mac-hash-algo", po::value<std::string>(), "The Message Authentication Code hash algorithm (must be set if "
                                                    "mac-algo is set. Default: SHA512. Available: SHA256, SHA384, "
                                                    "SHA512, SHA3-256, SHA3-384, SHA3-512")
        ("mac-key-size", po::value<uint>(), "The key size (in bits) for the MAC. Must be set if mac-algo is set. "
                                            "Default is 512 (as the default hash function is SHA-512)")
        ("kdf-algo", po::value<std::string>(), "The Key derivation function algorithm (optional. "
                                               "default: X963KDF. Available: X963KDF, PBKDF2)")
        ("kdf-hash-algo", po::value<std::string>(), "The Message Authentication Code hash algorithm (must be set if "
                                                    "kdf-algo is set. Available: SHA256, SHA384, SHA512, SHA3-256, "
                                                    "SHA3-384, SHA3-512")
        ("kdf-algo-iterations", po::value<uint>()->default_value(1024), "The number of iterations for PBKDF2. "
                                                                        "Default 1024")
        ("eph-key-form", po::value<std::string>(), "The form of the printed ephemeral key during encryption. "
                                                   "Values: uncompressed, hybrid, "
                                                   "compressed. Optional. Default: uncompressed")
    ;

    po::options_description cmdlineOptions;
    cmdlineOptions.add(get_generic_options_description())
                  .add(get_encryption_options_description())
                  .add(get_common_asymmetric_options_description())
                  .add(ecies_decrypt)
                  .add(ecies_optional);

    succeedOrExit(!parseCommandLineOptions(cmdlineOptions, vm, argc, argv), "Failure parsing command line.");

    if (vm.count("help") || argc == 1) {
        std::cerr << cmdlineOptions << "\n";
        exit(EXIT_SUCCESS);
    }

    succeedOrExit(!isEncryptionOptionsValid(vm), "");
    succeedOrExit(!isGetCommonAsymmetricOptionsValid(vm), "You need to specify a private key for encryption or a "
                                                          "cert/public key for decryption");

    if (vm.count("decrypt")) {
        succeedOrExit(!vm.count("eph-key"), "Ephemeral key is needed for decryption");
        succeedOrExit(!vm.count("mac-value"), "MAC value is needed for decryption");
    }

    // equivalence checks (both or none need to defined)
    succeedOrExit(vm.count("kdf-algo") xor vm.count("kdf-hash-algo"), "You need to specify the KDF algorithm AND "
                                                                      "its hash algorithm (--kdf-hash-algo)");
    succeedOrExit(vm.count("mac-algo") xor vm.count("mac-hash-algo"), "You need to specify the MAC algorithm AND "
                                                                      "its hash algorithm (--mac-hash-algo)");

    succeedOrExit(!vm.count("data"), "You need to specify some data for en-/decryption. "
                                     "For encryption you can also use an empty string ");
}

static std::unordered_map<std::string, openssl::EllipticCurvePointConversionForm> const formConversionMap = {
    {"compressed", openssl::EllipticCurvePointConversionForm::compressed},
    {"uncompressed", openssl::EllipticCurvePointConversionForm::uncompressed},
    {"hybrid",openssl::EllipticCurvePointConversionForm::hybrid}
};

openssl::EllipticCurvePointConversionForm getFormFromArguments(const po::variables_map &vm)
{
    if (!vm.count("eph-key-form")) {
        // Not set. Return the default value as stated in the argument description
        return openssl::EllipticCurvePointConversionForm::uncompressed;
    }

    std::string formString = vm["eph-key-form"].as<std::string>();

    auto it = formConversionMap.find(formString);
    if (it != formConversionMap.end()) {
        return it->second;
    }

    std::cerr << "Please select a valid point conversion form (uncompressed, hybrid or compressed)" << std::endl;
    exit(EXIT_FAILURE);
}

std::shared_ptr<KeyDerivationFunction> getKdfFromArguments(const po::variables_map &vm)
{
    std::string kdfString = vm["kdf-algo"].as<std::string>();
    openssl::DigestTypes digest = getDigestType(vm["kdf-hash-algo"].as<std::string>());

    if (!kdfString.compare("X963KDF")) {
        return std::make_shared<X963KDF>(digest);
    }
    else if (!kdfString.compare("PBKDF2")) {
        return std::make_shared<PBKDF2>(digest, vm["kdf-algo-iterations"].as<uint>());
    }

    std::cerr << "Please select a supported KDF algorithm. " << kdfString << " is invalid." << std::endl;
    exit(EXIT_FAILURE);
}

std::function<std::unique_ptr<MessageAuthenticationCode>(const std::vector<uint8_t>&)> getMacFromArguments(
        const po::variables_map &vm)
{
    std::string kdfString = vm["mac-algo"].as<std::string>();
    openssl::DigestTypes digest = getDigestType(vm["mac-hash-algo"].as<std::string>());

    if (!kdfString.compare("HMAC")) {
        return ([digest](const std::vector<uint8_t> &key) -> std::unique_ptr<MessageAuthenticationCode> {
               return std::make_unique<mococrw::HMAC>(digest, key);
           });
    }

    std::cerr << "Please select a supported KDF algorithm. " << kdfString << " is invalid." << std::endl;
    exit(EXIT_FAILURE);
}

size_t getMacKeySizeFromArguments(const po::variables_map &vm)
{
    if (vm.count("mac-key-size")) {
        size_t keySize = vm["mac-key-size"].as<uint>();
        succeedOrExit(keySize % 8, "Key size has to be a multiple of 8.");
        return keySize / 8;
    }

    std::cerr << "Please provide a key size in number of bits. "
                 "Usually this is the same as the length of the hash algorithm output (e.g. SHA256 -> 256)."
              << std::endl;
    exit(EXIT_FAILURE);
}

void parseCommonData(struct EciesData &eciesData, const po::variables_map &vm)
{
    if (vm.count("kdf-algo")) {
        eciesData.kdfFunc = getKdfFromArguments(vm);
    }

    if (vm.count("mac-algo")) {
        eciesData.macFunc = getMacFromArguments(vm);
        eciesData.macKeySize = getMacKeySizeFromArguments(vm);
    }

    if (vm.count("chaining")) {
        eciesData.chaining = true;
    }

    eciesData.data = utility::fromHex(vm["data"].as<std::string>());
}

void parseDecryptData(struct EciesData &eciesData, const po::variables_map &vm)
{
    parseCommonData(eciesData, vm);

    /* Set the received mac value */
    eciesData.macValue = utility::fromHex(vm["mac-value"].as<std::string>());

    eciesData.privKey = std::make_shared<AsymmetricPrivateKey>(loadPrivkeyFromFile(vm["private-key"].as<std::string>(),
                vm["private-key-password"].as<std::string>()));
    std::shared_ptr<AsymmetricKey::Spec> spec = eciesData.privKey->getKeySpec();
    eciesData.eccSpec = std::dynamic_pointer_cast<ECCSpec>(spec);
    succeedOrExit(!eciesData.eccSpec, "The private key is not an ECC key.");

    try {
        eciesData.ephKey = std::make_shared<AsymmetricPublicKey>(AsymmetricPublicKey::fromECPoint(eciesData.eccSpec,
                                                            utility::fromHex(vm["eph-key"].as<std::string>())));
    } catch (MoCOCrWException &e) {
        std::cerr << "Error getting ephemeral key." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

void parseEncryptData(struct EciesData &eciesData, const po::variables_map &vm)
{
    parseCommonData(eciesData, vm);
    if (vm.count("public-key")) {
        try {
            eciesData.pubKey = std::make_shared<AsymmetricPublicKey>(loadPubkeyFromFile(
                        vm["public-key"].as<std::string>()));
        }  catch (openssl::OpenSSLException &e) {
            std::cerr << "Can't read public key in PEM format from key file: "
                      << vm["public-key"].as<std::string>() << std::endl;
            exit(EXIT_FAILURE);
        }
        succeedOrExit(!isPubKeyAnEccKey(*eciesData.pubKey.get()),
                      "No ECC key is provided. Please provide an elliptic curve public key.");
        return;
    }

    /* we got a certificate */
    try {
        eciesData.cert = std::make_shared<X509Certificate>(loadCertFromFile(vm["cert"].as<std::string>()));
        succeedOrExit(!isPubKeyAnEccKey(eciesData.cert->getPublicKey()), "No ECC key is provided. Please provide a "
                                                                         "certificate containing an elliptic curve "
                                                                         "public key.");
    }  catch (openssl::OpenSSLException &e) {
        std::cerr << "Can't read certificate in PEM format from cert file: "
                  << vm["cert"].as<std::string>() << std::endl;
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char *argv[])
{

    auto vm = std::make_shared<po::variables_map>();
    struct EciesData eciesData;
    parseCommandlineArgs(argc, argv, *vm.get());
    eciesData.vm = vm;
    try {
        if ((*vm.get()).count("decrypt")) {
            parseDecryptData(eciesData, *vm.get());
            decrypt_ecies(eciesData);
        } else {
            parseEncryptData(eciesData, *vm.get());
            encrypt_ecies(eciesData);
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
