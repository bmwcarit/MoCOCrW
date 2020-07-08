#include <iostream>
#include <unordered_map>

#include <boost/program_options.hpp>

#include <mococrw/ecies.h>
#include <mococrw/x509.h>

#include "common.h"
#include "IOUtils.h"
#include "parsingUtils.h"

namespace po = boost::program_options;
using namespace mococrw;

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
                                            "Default is 512 (as the hash function is SHA-512")
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
                  .add(ecies_decrypt)
                  .add(ecies_optional);


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

    succeedOrExit(!isEncryptionOptionsValid(vm), "You can either decrypt or encrypt the data");
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

openssl::EllipticCurvePointConversionForm getFormFromArguments(po::variables_map vm)
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

std::shared_ptr<KeyDerivationFunction> getKdfFromArguments(po::variables_map vm)
{
    std::string kdfString = vm["kdf-algo"].as<std::string>();
    openssl::DigestTypes digest = getDigest(vm["kdf-hash-algo"].as<std::string>());

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
        po::variables_map vm)
{
    std::string kdfString = vm["mac-algo"].as<std::string>();
    openssl::DigestTypes digest = getDigest(vm["mac-hash-algo"].as<std::string>());

    if (!kdfString.compare("HMAC")) {
        return ([digest](const std::vector<uint8_t> &key) -> std::unique_ptr<MessageAuthenticationCode> {
               return std::make_unique<mococrw::HMAC>(digest, key);
           });
    }

    std::cerr << "Please select a supported KDF algorithm. " << kdfString << " is invalid." << std::endl;
    exit(EXIT_FAILURE);
}

size_t getMacKeySizeFromArguments(po::variables_map vm)
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

bool isPubKeyAnEccKey(AsymmetricPublicKey pubKey)
{
    std::shared_ptr<AsymmetricKey::Spec> spec = pubKey.getKeySpec();
    auto eccSpec = std::dynamic_pointer_cast<ECCSpec>(spec);
    if (eccSpec) {
        /* The key is an ECC key */
        return true;
    }
    return false;
}

std::unique_ptr<ECIESEncryptionCtx> buildEncryptionContext(po::variables_map vm)
{
    ECIESCtxBuilder encBuilder;
    std::unique_ptr<ECIESEncryptionCtx> encCtx;

    if (vm.count("kdf-algo")) {
        encBuilder.setKDF(getKdfFromArguments(vm));
    }

    if (vm.count("mac-algo")) {
        encBuilder.setMacFactoryFunction(getMacFromArguments(vm));
        encBuilder.setMacKeySize(getMacKeySizeFromArguments(vm));
    }

    if (vm.count("public-key")) {
        AsymmetricPublicKey pubKey(nullptr);
        try {
            pubKey = loadPubkeyFromFile(vm["public-key"].as<std::string>());
        }  catch (openssl::OpenSSLException &e) {
            std::cerr << "Can't read public key in PEM format from key file: "
                      << vm["public-key"].as<std::string>() << std::endl;
            exit(EXIT_FAILURE);
        }

        succeedOrExit(!isPubKeyAnEccKey(pubKey), "No ECC key is provided. Please provide an elliptic curve "
                                                 "public key.");

        return encBuilder.buildEncryptionCtx(pubKey);
    }

    /* we got a certificate */
    try {
        auto cert = loadCertFromFile(vm["cert"].as<std::string>());
        succeedOrExit(!isPubKeyAnEccKey(cert.getPublicKey()), "No ECC key is provided. Please provide an "
                                                              "elliptic curve public key.");
        return encBuilder.buildEncryptionCtx(cert);
    }  catch (openssl::OpenSSLException &e) {
        std::cerr << "Can't read certificate in PEM format from cert file: "
                  << vm["cert"].as<std::string>() << std::endl;
        exit(EXIT_FAILURE);
    }
}

std::unique_ptr<ECIESDecryptionCtx> buildDecryptionContext(po::variables_map vm)
{
    ECIESCtxBuilder decBuilder;

    if (vm.count("kdf-algo")) {
        decBuilder.setKDF(getKdfFromArguments(vm));
    }

    if (vm.count("mac-algo")) {
        decBuilder.setMacFactoryFunction(getMacFromArguments(vm));
        decBuilder.setMacKeySize(getMacKeySizeFromArguments(vm));
    }

    auto privKey = loadPrivkeyFromFile(vm["private-key"].as<std::string>(),
                vm["private-key-password"].as<std::string>());
    std::shared_ptr<AsymmetricKey::Spec> spec = privKey.getKeySpec();
    auto eccSpec = std::dynamic_pointer_cast<ECCSpec>(spec);
    succeedOrExit(!eccSpec, "The private key is not an ECC key.");
    AsymmetricPublicKey ephKey = AsymmetricPublicKey::fromECPoint(eccSpec,
                                                                  utility::fromHex(vm["eph-key"].as<std::string>()));

    return decBuilder.buildDecryptionCtx(privKey, ephKey);
}

void printChainingData(po::variables_map vm)
{
    if (vm.count("kdf-algo")) {
        std::cout << "--kdf-algo " << (vm["kdf-algo"].as<std::string>()) << " ";
        std::cout << "--kdf-hash-algo " << vm["kdf-hash-algo"].as<std::string>() << " ";
    }

    if (vm.count("mac-algo")) {
        std::cout << "--mac-algo " << vm["mac-algo"].as<std::string>() << " ";
        std::cout << "--mac-hash-algo " << vm["mac-hash-algo"].as<std::string>() << " ";
        std::cout << "--mac-key-size " << std::to_string(vm["mac-key-size"].as<uint>()) << " ";
    }
}

void encrypt_ecies(po::variables_map vm)
{
    printVerbose("Encrypting using ECIES");

    std::unique_ptr<ECIESEncryptionCtx> encCtx = buildEncryptionContext(vm);

    encCtx->update(utility::fromHex(vm["data"].as<std::string>()));

    if (vm.count("chaining")) {
        printChainingData(vm);
        std::cout << "--data " << utility::toHex(encCtx->finish()) << " ";
        std::cout << "--eph-key " << utility::toHex(encCtx->getEphemeralKey().toECPoint(getFormFromArguments(vm)))
                  << " ";
        std::cout << "--mac-value " << utility::toHex(encCtx->getMAC()) << std::endl;
        return;
    }

    std::cout << "Ciphertext: " << utility::toHex(encCtx->finish()) << std::endl;
    std::cout << "Ephemeral key: " << utility::toHex(encCtx->getEphemeralKey().toECPoint(getFormFromArguments(vm)))
              << std::endl;
    std::cout << "MAC: " << utility::toHex(encCtx->getMAC()) << std::endl;
}

void decrypt_ecies(po::variables_map vm)
{
//    std::cout << "Decrypting using ECIES" << std::endl;
    /* We need
     * - mac value
     * - ephemeral key
     * - private key
     */

    /* Use the default values, which should match here. */
    auto decCtx = buildDecryptionContext(vm);

    /* Decrypt the ciphertext */
    decCtx->update(utility::fromHex(vm["data"].as<std::string>()));

    /* Set the received mac value */
    decCtx->setMAC(utility::fromHex(vm["mac-value"].as<std::string>()));

    /* Get the plaintext and verify the MAC */
    auto result = decCtx->finish();

    printVerbose("Decrypted data:");
    std::cout << utility::toHex(result) << std::endl;
}

int main(int argc, char *argv[])
{

    po::variables_map vm;
    parseCommandlineArgs(argc, argv, vm);
    try {
        if (vm.count("decrypt")) {
            decrypt_ecies(vm);
        } else {
            encrypt_ecies(vm);
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

