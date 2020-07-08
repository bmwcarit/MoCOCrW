#include <iostream>
#include <string>

#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

#include <mococrw/x509.h>
#include <mococrw/asymmetric_crypto_ctx.h>
#include <mococrw/key.h>

#include "common.h"
#include "IOUtils.h"
#include "parsingUtils.h"

namespace po = boost::program_options;
using namespace mococrw;


void parseCommandlineArgs(int argc, char *argv[], po::variables_map &vm)
{
    po::options_description genericSignVerifyOptions("Generic options for signing and verifying");
    genericSignVerifyOptions.add_options()
        ("message", po::value<std::string>(), "Message to be signed or verified in hex form (with or without 0x "
                                              "prepended)")
        ("signature", po::value<std::string>(), "Signature to verify in hex form (with or without 0x "
                                                "prepended). Optional: Only for needed for --verify")
        ("hash-algo", po::value<std::string>()->default_value("SHA256"),
            "The hash algorith used for digest calculation. Default: SHA-256"
            "Available: SHA256, SHA384, SHA512, SHA3-256, SHA3-384, SHA3-512"
            "Ignored for EdDSA!"
        )
    ;
    po::options_description rsaSignVerify("RSA related arguments for sigining and verifying");
    rsaSignVerify.add_options()
        ("padding", po::value<std::string>(), "The padding used for RSA en/decryption. Optional. Default: PSS. "
                                              "Available: PSS, PKCS")
        ("pss-salt-len", po::value<int>(), "The lenght of the PSS salt. Optional. Default: Size of output length of "
                                            "underlying hash function")
    ;

    po::options_description eccSignVerify("ECC related arguments for sigining and verifying");
    eccSignVerify.add_options()
        ("signature-format", po::value<std::string>(), "The signature format for the output. Optional. Default: ASN1.\n"
                                                       "Available:\n- ASN1 (Encoding of (r,s) as ASN.1 sequence of "
                                                       "integers as specified in ANSI X9.62),\n- IEEE1363 (Encoding of "
                                                       "(r,s) as raw big endian unsigned integers zero-padded to the "
                                                       "key length as specified in IEEE 1363)")
            ;

    po::options_description cmdlineOptions;
    cmdlineOptions.add(get_generic_options_description())
                  .add(get_asymmetric_sign_and_verify_options_description())
                  .add(get_common_asymmetric_options_description())
                  .add(genericSignVerifyOptions)
                  .add(rsaSignVerify)
                  .add(eccSignVerify);

    try {
        po::store(po::parse_command_line(argc, argv, cmdlineOptions), vm);
    } catch (boost::wrapexcept<boost::program_options::invalid_command_line_syntax> &e) {
        std::cerr << "Failure parsing the input. Please check your input!" << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    } catch (boost::wrapexcept<boost::program_options::invalid_option_value> &e) {
        std::cerr << "Got invalid option value (e.g. string for integer). Please check your input!" << std::endl;
        exit(EXIT_FAILURE);
    } catch (boost::exception &e) {
        std::cerr << "Caught boost exception during parsing. Please check your input!" << std::endl;
        exit(EXIT_FAILURE);
    }
    po::notify(vm);

    if (vm.count("help") || argc == 1) {
        std::cerr << cmdlineOptions << "\n";
        exit(EXIT_SUCCESS);
    }

    // antivalence check (only one must be defined)
    succeedOrExit(!isGetAsymmetricSignAndVerfyOptionsValid(vm), "You can either sign or verify the data");
    succeedOrExit(!isGetCommonAsymmetricOptionsValid(vm), "You need to specify a private key for signing or a "
                                                          "cert/public key for verification");
    succeedOrExit((vm.count("padding") && vm.count("pss-salt-len") && vm["padding"].as<std::string>().compare("pss")) ||
            (!vm.count("padding") && vm.count("pss-salt-len")),
            "Use --pss-salt-len only with --padding pss");
    succeedOrExit((vm.count("verify") && !vm.count("signature")), "You need to speciy a signature which shall be "
                                                                   "verified");

}

std::shared_ptr<RSASignaturePadding> getRsaPadding(const po::variables_map &vm)
{
    if (!vm.count("padding")) {
        /* Default is OAEP padding */
        return std::make_shared<PSSPadding>();
    }

    std::string paddingString = boost::to_upper_copy<std::string>(vm["padding"].as<std::string>());
    if (!paddingString.compare("PKCS")) {
        return std::make_shared<PKCSPadding>();
    } else if (!paddingString.compare("PSS")) {
        boost::optional<int> saltLength = boost::none;
        if (vm.count("pss-salt-len")) {
            // The input is already validated during parsing, so it has to be something like an int
            saltLength = vm["pss-salt-len"].as<int>();
        }
        // The first option is the MGF. As we only support MGF1 (which is the default) this can be a nullptr
        return std::make_shared<PSSPadding>(nullptr, saltLength);
    }

    std::cerr << "Please select a supported Padding scheme. " << paddingString << " is invalid." << std::endl;
    exit(EXIT_FAILURE);
}


std::shared_ptr<MessageSignatureCtx> signRsa(const po::variables_map &vm, const AsymmetricPrivateKey &&key)
{
    std::shared_ptr<MessageSignatureCtx> ctx(nullptr);
    std::shared_ptr<RSASignaturePadding> padding(getRsaPadding(vm));

    openssl::DigestTypes digest = getDigest(vm["hash-algo"].as<std::string>());
    printVerbose("Using " << vm["hash-algo"].as<std::string>() << " as hash algorithm.");
    try {
        ctx = std::make_shared<RSASignaturePrivateKeyCtx>(key, digest);
    }  catch (MoCOCrWException &e) {
        std::cerr << "Please check your RSA key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
    return ctx;
}

ECDSASignatureFormat getSigFormat(const po::variables_map &vm)
{
    if (!vm.count("signature-format")) {
        return ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS;
    }

    std::string format = vm["signature-format"].as<std::string>();
    if (format.compare("ASN1")) {
        return ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS;
    } else if (format.compare("IEEE1363")) {
        return ECDSASignatureFormat::IEEE1363;
    }

    std::cerr << "Please select a valid signature format for ECIES. " << format << " is invalid." << std::endl;
    exit(EXIT_FAILURE);
}

std::shared_ptr<MessageSignatureCtx>signEcc(const po::variables_map &vm, const AsymmetricPrivateKey &&key)
{

    std::shared_ptr<MessageSignatureCtx> ctx(nullptr);
    openssl::DigestTypes digest = getDigest(vm["hash-algo"].as<std::string>());
    printVerbose("Using " << vm["hash-algo"].as<std::string>() << " as hash algorithm.");
    try {
        ctx = std::make_shared<ECDSASignaturePrivateKeyCtx>(key, digest, getSigFormat(vm));
    }  catch (MoCOCrWException &e) {
        std::cerr << "Please check your ECC key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
    return ctx;
}

std::shared_ptr<MessageSignatureCtx>signEccEd(const AsymmetricPrivateKey &&key)
{
    std::shared_ptr<MessageSignatureCtx> ctx(nullptr);
    try {
        ctx = std::make_shared<EdDSASignaturePrivateKeyCtx>(key);
    }  catch (MoCOCrWException &e) {
        std::cerr << "Please check your ECC-Ed key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
    return ctx;
}


void sign(const po::variables_map &vm)
{
    AsymmetricPrivateKey privKey(nullptr);
    try {
        privKey = loadPrivkeyFromFile(vm["private-key"].as<std::string>(),
                    vm["private-key-password"].as<std::string>());
    }  catch (openssl::OpenSSLException &e) {
        std::cerr << "Failure to load the private key for signing. Please check your key." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    std::shared_ptr<MessageSignatureCtx> signCtx;
    switch(privKey.getType()) {
    case AsymmetricKey::KeyTypes::RSA:
        signCtx = signRsa(vm, std::move(privKey));
        break;
    case AsymmetricKey::KeyTypes::ECC:
        signCtx = signEcc(vm, std::move(privKey));
        break;
    case AsymmetricKey::KeyTypes::ECC_ED:
        signCtx = signEccEd(std::move(privKey));
        break;
    default:
        std::cerr << "Unknown key type. Supported are RSA, ECC and ECC_ED";
        exit(EXIT_FAILURE);
    }

    std::vector<uint8_t> signature;
    try {
        signature = signCtx->signMessage(utility::fromHex(vm["message"].as<std::string>()));
    }  catch (MoCOCrWException &e) {
        std::cerr << "Failure occured during signing." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    if (vm.count("chaining")) {
        if (vm.count("padding")) {
            std::cout << "--padding " << vm["padding"].as<std::string>() << " ";
            if (vm.count("pss-salt-len")) {
                std::cout << "--pss-salt-len " << vm["pss-salt-len"].as<std::string>() << " ";
            }
        }

        if (vm.count("hash-algo")) {
            std::cout << "--hash-algo " << vm["hash-algo"].as<std::string>() << " ";
        }

        if (vm.count("signature-format") && privKey.getType() == AsymmetricKey::KeyTypes::ECC) {
            std::cout << "--signature-format " << vm["signature-format"].as<std::string>() << " ";
        }

        std::cout << "--message " << vm["message"].as<std::string>() << " ";
        std::cout << "--signature ";
    }

    std::cout << utility::toHex(signature) << std::endl;

}

std::shared_ptr<MessageVerificationCtx> verifyRsa(const po::variables_map &vm, const AsymmetricPublicKey &&key)
{
    std::shared_ptr<MessageVerificationCtx> ctx(nullptr);
    std::shared_ptr<RSASignaturePadding> padding(getRsaPadding(vm));

    openssl::DigestTypes digest = getDigest(vm["hash-algo"].as<std::string>());
    printVerbose("Using " << vm["hash-algo"].as<std::string>() << " as hash algorithm.");

    try {
        ctx = std::make_shared<RSASignaturePublicKeyCtx>(key, digest);
    }  catch (MoCOCrWException &e) {
        std::cerr << "Please check your RSA key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
    return ctx;
}

std::shared_ptr<MessageVerificationCtx> verifyEcc(const po::variables_map &vm, const AsymmetricPublicKey &&key)
{
    std::shared_ptr<MessageVerificationCtx> ctx(nullptr);

    openssl::DigestTypes digest = getDigest(vm["hash-algo"].as<std::string>());
    printVerbose("Using " << vm["hash-algo"].as<std::string>() << " as hash algorithm.");

    try {
        ctx = std::make_shared<ECDSASignaturePublicKeyCtx>(key, digest);
    }  catch (MoCOCrWException &e) {
        std::cerr << "Please check your ECC key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
    return ctx;
}

std::shared_ptr<MessageVerificationCtx> verifyEccEd(const AsymmetricPublicKey &&key)
{
    std::shared_ptr<MessageVerificationCtx> ctx(nullptr);
    try {
        ctx = std::make_shared<EdDSASignaturePublicKeyCtx>(key);
    }  catch (MoCOCrWException &e) {
        std::cerr << "Please check your ECC-Ed key. Failure creating context." << std::endl;
        std::cerr << e.what();
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void verify(const po::variables_map &vm)
{
    AsymmetricPublicKey pubKey(nullptr);
    try {
        pubKey = loadPubkeyFromFile(vm["public-key"].as<std::string>());
    }  catch (openssl::OpenSSLException &e) {
        std::cerr << "Failure to load the private key for signing. Please check your key." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    std::shared_ptr<MessageVerificationCtx> verifyCtx;
    switch(pubKey.getType()) {
    case AsymmetricKey::KeyTypes::RSA:
        verifyCtx = verifyRsa(vm, std::move(pubKey));
        printVerbose("Got a RSA key for verification.");
        break;
    case AsymmetricKey::KeyTypes::ECC:
        verifyCtx = verifyEcc(vm, std::move(pubKey));
        printVerbose("Got an ECC key for verification.");
        break;
    case AsymmetricKey::KeyTypes::ECC_ED:
        verifyCtx = verifyEccEd(std::move(pubKey));
        printVerbose("Got an ECC-Ed key for verification.");
        break;
    default:
        std::cerr << "Unknown key type. Supported are RSA, ECC and ECC_ED";
        exit(EXIT_FAILURE);
    }

    std::vector<uint8_t> signature = utility::fromHex(vm["signature"].as<std::string>());

    try {
        verifyCtx->verifyMessage(utility::fromHex(vm["signature"].as<std::string>()),
                                 utility::fromHex(vm["message"].as<std::string>()));
    } catch (MoCOCrWException &e) {
        std::cerr << "Verification failed!" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "Verification successful. Signature is valid!" << std::endl;

}

int main(int argc, char* argv[])
{
    po::variables_map vm;
    parseCommandlineArgs(argc, argv, vm);

    if (vm.count("sign")) {
        sign(vm);
    } else {
        verify(vm);
    }

    return 0;
}
