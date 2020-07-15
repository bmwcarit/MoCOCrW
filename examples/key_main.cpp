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
#include "mococrw/private/parsingUtils.h"

#include "key_example.h"

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

    succeedOrExit(!parseCommandLineOptions(cmdlineOptions, vm, argc, argv), "Failure parsing command line.");

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

void parseKeyData(struct KeyData &keyData)
{
    auto vm = *keyData.vm.get();
    keyData.password = getPassword(vm);

    if (vm.count("curve")) {
        keyData.curve = getCurve(vm);
    }

    if (vm.count("key-size")) {
        keyData.keySize = vm["key-size"].as<uint>();
    }

    if (vm.count("out-file")) {
        keyData.outFile = vm["out-file"].as<std::string>();
    }

    if (vm.count("pub-out")) {
        keyData.pubOut = true;
    }

    if (vm.count("pub-out-file")) {
        keyData.pubOutFile = vm["pub-out-file"].as<std::string>();
    }

    if (vm.count("rsa")) {
        keyData.rsa = true;
        // otherwise we create an ecc key
    }
}

int main(int argc, char *argv[])
{
    auto vm = std::make_shared<po::variables_map>();
    parseCommandlineArgs(argc, argv, *vm.get());
    KeyData keyData(vm);

    parseKeyData(keyData);
    createKey(keyData);
    return 0;
}
