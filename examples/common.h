#pragma once

#include <unordered_map>
#include <fstream>
#include <iostream>

#include <boost/program_options.hpp>
#include <mococrw/hash.h>


#define succeedOrExit(condition, ...) do { \
        if (condition) { \
            std::cerr << __VA_ARGS__ << std::endl; \
            exit(EXIT_FAILURE); \
        } \
    } while(0)

#define printVerbose(...) do { \
        if (vm.count("verbose")) { \
            std::cout << __VA_ARGS__ << std::endl; \
        } \
    } while(0)

namespace po = boost::program_options;

po::options_description get_generic_options_description()
{
    po::options_description generic("Common options");
    generic.add_options()
            ("help,h", "This help")
            ("verbose", "Verbose output")
    ;
    return generic;
}

po::options_description get_encryption_options_description()
{
    po::options_description desc("Options for asymmetric encryption and decryption");
    desc.add_options()
            ("encrypt", "Encrypt the data")
            ("decrypt", "Decrypt the data")
            ("data", po::value<std::string>(), "Data to en-/decrypt in hex form (with or without 0x "
                                               "prepended)")
            ("chaining", "Print results in a form that they can be used as command line arguments for "
                         "decryption/verification. Can't be combined with verbose")
            ;
    return desc;
}

bool isEncryptionOptionsValid(const po::variables_map &vm)
{
    // antivalence check (only one must be defined)
    if (!(vm.count("decrypt") xor vm.count("encrypt"))) {
        return false;
    }

    if (vm.count("verbose") && vm.count("chaining")) {
        // Either verbose or chaining can be selected
        return false;
    }

    return true;
}

po::options_description get_asymmetric_sign_and_verify_options_description()
{
    po::options_description signVerify("Options for asymmetric signatures and verification");
    signVerify.add_options()
            ("sign", "Sign the data")
            ("verify", "Verify the data")
            ;
    return signVerify;
}

bool isGetAsymmetricSignAndVerfyOptionsValid(const po::variables_map &vm)
{
    if (!(vm.count("sign") xor vm.count("verify"))) {
        return false;
    }
    return true;
}

po::options_description get_common_asymmetric_options_description()
{
    po::options_description commonAsymmetricOptions("Common options for asymmetric cryptography");
    commonAsymmetricOptions.add_options()
            ("private-key", po::value<std::string>(), "Path to the private key for decryption/signing")
            ("private-key-password", po::value<std::string>()->default_value(""), "Optional: password for the private key")
            ("public-key", po::value<std::string>(), "Path to the public key for encryption/verifying")
            ("cert", po::value<std::string>(), "Path to the certificate used for encryption/verifying")
            ;
    return commonAsymmetricOptions;
}

bool isGetCommonAsymmetricOptionsValid(const po::variables_map &vm)
{
    if (vm.count("decrypt") || vm.count("sign")) {
        if (!vm.count("private-key")) {
            return false;
        }
    } else {
        if (!(vm.count("public-key") xor vm.count("cert"))) {
            return false;
        }
    }
    return true;
}
