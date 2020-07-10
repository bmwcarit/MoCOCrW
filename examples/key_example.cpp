#include <iostream>
#include <fstream>
#include <unordered_map>
#include <string>

#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

#include <mococrw/key.h>

#include "common.h"
#include "IOUtils.h"
#include "parsingUtils.h"

namespace po = boost::program_options;
using namespace mococrw;

void parseCommandlineArgs(int argc, char *argv[], po::variables_map &vm)
{
    po::options_description genericKeyOptions("Generic options for key generation. Only PEM format is supported.");
    genericKeyOptions.add_options()
            ("rsa", "Create a RSA key")
            ("ecc", "Create an ECC key")
            ("out-file", po::value<std::string>(), "The path to store the key. If omitted the key will be printed to "
                                                   "stdout")
            ("password", po::value<std::string>(), "The password for storing the key. Optional.")
            ("pub-out", "Print public key.")
            ("pub-out-file", po::value<std::string>(), "The path to store the public key. If omitted the public key "
                                                       "will be printed to stdout")
            ;

    po::options_description keyOptions("Options for RSA keys");
    keyOptions.add_options()
            ("key-size", po::value<uint>()->default_value(2048),"The size of the RSA key. Default: 2048")
            ;

    po::options_description eccKeyOptions("Options for ECC keys");
    eccKeyOptions.add_options()
            ("curve", po::value<std::string>()->default_value("PRIME_256v1"),
             "The curve to use for key generation. Available: PRIME_192v1, PRIME_256v1, SECP_224r1, SECP_384r1, "
             "SECP_521r1, SECT_283k1, SECT_283r1, SECT_409k1, SECT_409r1, SECT_571k1, SECT_571r1, Ed448, Ed25519. "
             "\nThis option is case SeNsItIvE!")
            ;

    po::options_description cmdlineOptions;
    cmdlineOptions.add(get_generic_options_description())
            .add(genericKeyOptions)
            .add(keyOptions)
            .add(eccKeyOptions);

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
    }

    po::notify(vm);

    if (vm.count("help") || argc == 1) {
        std::cerr << cmdlineOptions << "\n";
        exit(EXIT_SUCCESS);
    }

    succeedOrExit(!(vm.count("rsa") xor vm.count("ecc")), "Select either --rsa or --ecc");
    succeedOrExit(vm.count("pub-out-file") && !vm.count("pub-out"), "If --pub-out-file is specified --pub-out is "
                                                                       "required");
}

openssl::ellipticCurveNid getCurve(const po::variables_map &vm)
{
    bool success = false;
    openssl::ellipticCurveNid retNid = getEllipticCurveNid(vm["curve"].as<std::string>(), success);
    if (!success) {
        std::cerr << "Failure parsing curve " << vm["curve"].as<std::string>() << std::endl;
        exit(EXIT_FAILURE);
    }
    return retNid;
}

std::string getPassword(const po::variables_map &vm)
{
    if (vm.count("password")) {
        return vm["password"].as<std::string>();
    }
    return "";
}

void printKeyToFile(const std::string &pem, const std::string &filename)
{
    std::ofstream file{filename, std::ofstream::out};
    if (!file.good()) {
        std::string errorMsg{"Cannot open file for writing key."};
        errorMsg = errorMsg + filename;
        exit(EXIT_FAILURE);
    }

    file << pem;
    file.close();
}

void printPublicKey(const po::variables_map &vm, const std::string &pubPem)
{
    if (!vm.count("pub-out")) {
        return;
    }
    if (vm.count("pub-out-file")) {
        printKeyToFile(pubPem, vm["pub-out-file"].as<std::string>());
    } else {
        std::cout << pubPem << std::endl;
    }
}

void createKey(const po::variables_map &vm)
{
    uint keySize = vm["key-size"].as<uint>();
    std::shared_ptr<AsymmetricKey::Spec> spec;
    if (vm.count("rsa")) {
        spec = std::make_shared<RSASpec>(keySize);
    } else {
        spec = std::make_shared<ECCSpec>(getCurve(vm));
    }
    auto key = AsymmetricKeypair::generate(*spec);

    auto pem = key.privateKeyToPem(getPassword(vm));
    std::string pubPem;

    if (vm.count("pub-out")) {
        pubPem = key.publicKeyToPem();
    }

    if (vm.count("out-file")) {
        printKeyToFile(pem, vm["out-file"].as<std::string>());
        printPublicKey(vm, pubPem);
    } else {
        std::cout << pem << std::endl;
        printPublicKey(vm, pubPem);
    }
}

int main(int argc, char *argv[])
{
    po::variables_map vm;
    parseCommandlineArgs(argc, argv, vm);

    createKey(vm);
    return 0;
}
