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
#include "mococrw/private/IOUtils.h"
#include "mococrw/private/parsingUtils.h"

#include "sig_example.h"

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
        ("chaining", "Print results in a form that they can be used as command line arguments for "
                     "decryption/verification. Can't be combined with verbose")
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

    succeedOrExit(!parseCommandLineOptions(cmdlineOptions, vm, argc, argv), "Failure parsing command line.");

    if (vm.count("help") || argc == 1) {
        std::cerr << cmdlineOptions << "\n";
        exit(EXIT_SUCCESS);
    }

    succeedOrExit(!isGetAsymmetricSignAndVerfyOptionsValid(vm), "You can either sign or verify the data");
    succeedOrExit(!isGetCommonAsymmetricOptionsValid(vm), "You need to specify a private key for signing or a "
                                                          "cert/public key for verification");
    succeedOrExit((vm.count("padding") && vm.count("pss-salt-len")
                   && !boost::to_upper_copy<std::string>(vm["padding"].as<std::string>()).compare("pss")) ||
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

void parseCommonData(SigData &sigData)
{
    auto vm = *sigData.vm.get();
    if (vm.count("chaining")) {
        sigData.chaining = true;
    }

    try {
        sigData.message = utility::fromHex(vm["message"].as<std::string>());
    }  catch (MoCOCrWException &e) {
        std::cerr << "Failure reading message." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    sigData.digestType = getDigestType(vm["hash-algo"].as<std::string>());
    if (sigData.digestType == DigestTypes::NONE) {
        std::cerr << "Error parsing hash algorithm: " << vm["hash-algo"].as<std::string>() <<  std::endl;
        exit(EXIT_FAILURE);
    }

    if (vm.count("signature-format")) {
        sigData.sigFormat = getSigFormat(vm);
    } else {
        sigData.sigFormat = ECDSASignatureFormat::ASN1_SEQUENCE_OF_INTS;
    }
}

void parseSignData(SigData &sigData)
{
    auto vm = *sigData.vm.get();
    parseCommonData(sigData);
    try {
        sigData.privKey = std::make_shared<AsymmetricPrivateKey>(loadPrivkeyFromFile(vm["private-key"].as<std::string>(),
                    vm["private-key-password"].as<std::string>()));
    }  catch (openssl::OpenSSLException &e) {
        std::cerr << "Failure to load the private key for signing. Please check your key." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

void parseVerifyData(SigData &sigData)
{
    auto vm = *sigData.vm.get();
    parseCommonData(sigData);
    try {
        if (vm.count("public-key")) {
            sigData.pubKey = std::make_shared<AsymmetricPublicKey>(loadPubkeyFromFile(
                                                                       vm["public-key"].as<std::string>()));
        } else {
            auto  cert = loadCertFromFile(vm["cert"].as<std::string>());
            sigData.pubKey = std::make_shared<AsymmetricPublicKey>(cert.getPublicKey());
        }
        sigData.signature = utility::fromHex(vm["signature"].as<std::string>());
    }  catch (openssl::OpenSSLException &e) {
        std::cerr << "Failure to load the public key/certificatae or signature." << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char* argv[])
{
    auto vm = std::make_shared<po::variables_map>();
    parseCommandlineArgs(argc, argv, *vm.get());
    SigData sigData(vm);

    if ((*vm.get()).count("sign")) {
        parseSignData(sigData);
        sign(sigData);
    } else {
        parseVerifyData(sigData);
        verify(sigData);
    }

    return 0;
}
