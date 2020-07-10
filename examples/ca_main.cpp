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

#include "ca_example.h"


namespace po = boost::program_options;
namespace pt = boost::property_tree;
using namespace mococrw;

std::shared_ptr<BasicConstraintsExtension> getBasicConstraintsExtension(pt::ptree basicConstraintsSubTree)
{
    bool isCA = basicConstraintsSubTree.get("isCA", false);
    int pathlen = basicConstraintsSubTree.get("pathlength", 0);
    return std::make_shared<BasicConstraintsExtension>(isCA, pathlen);
}

template <class Builder, class Type>
Builder invokeIfTrue(Builder b, std::function<Builder ()> func, Type val)
{
    if (!val) {
        return b;
    }
    return func();
}

#define addKeyUsageIfTrue(func, str) \
    keyUsageBuilder = invokeIfTrue<KeyUsageExtension::Builder, bool>( \
        keyUsageBuilder, \
        std::bind(&KeyUsageExtension::Builder::func, keyUsageBuilder), \
        keyUsageSubTree.get(str, false) \
    )

std::shared_ptr<KeyUsageExtension> getKeyUsageExtension(pt::ptree keyUsageSubTree)
{
    auto keyUsageBuilder = KeyUsageExtension::Builder{};
    addKeyUsageIfTrue(decipherOnly, "decipherOnly");
    addKeyUsageIfTrue(encipherOnly, "encipherOnly");
    addKeyUsageIfTrue(cRLSign, "cRLSign");
    addKeyUsageIfTrue(keyCertSign, "keyCertSign");
    addKeyUsageIfTrue(keyAgreement, "keyAgreement");
    addKeyUsageIfTrue(dataEncipherment, "dataEncipherment");
    addKeyUsageIfTrue(keyEncipherment, "keyEncipherment");
    addKeyUsageIfTrue(nonRepudiation, "nonRepudiation");
    addKeyUsageIfTrue(digitalSignature, "digitalSignature");
    return std::make_shared<KeyUsageExtension>(keyUsageBuilder.build());
}
#undef addKeyUsageIfTrue

std::shared_ptr<CertificateSigningParameters> getSigningParams(const pt::ptree &propertyTree,
                                                               const std::string &treePrefix)
{

    auto keyUsage = getKeyUsageExtension(propertyTree.get_child(treePrefix + ".keyUsage"));
    auto basicConstraints = getBasicConstraintsExtension(propertyTree.get_child(treePrefix + ".basicConstraints"));
    auto digestType = getDigestType(propertyTree.get(treePrefix + ".digestType", ""));

    if (digestType == DigestTypes::NONE) {
        std::cerr << "You need to specify a digest type in your sign section in the configuration file." << std::endl;
        exit(EXIT_FAILURE);
    }

    // Subtract -1 to avoid race conditions while testing or instant use
    Asn1Time notBefore(Asn1Time::now() - std::chrono::seconds(1));
    auto notBeforeString = propertyTree.get(treePrefix + ".notBeforeAsn1", "");
    if (!notBeforeString.empty()) {
        try {
            notBefore = Asn1Time::fromString(notBeforeString);
        }  catch (openssl::OpenSSLException &e) {
            std::cerr << "Failure parsing notBeforeAsn1 time: " << notBeforeString << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    int64_t validitySeconds = propertyTree.get(treePrefix + ".certificateValiditySeconds", 0);
    if (!validitySeconds) {
        std::cerr << "You need to specify the validity period (validitySeconds) for certificates." << std::endl;
        exit(EXIT_FAILURE);
    }

    return std::make_shared<CertificateSigningParameters>(CertificateSigningParameters::Builder{}
            .certificateValidity(Asn1Time::Seconds(validitySeconds))
            .notBeforeAsn1(notBefore)
            .digestType(digestType)
            .addExtension(*basicConstraints)
            .addExtension(*keyUsage)
            .build());
}

void printSectionDescription()
{
    std::cout << "{" << std::endl;
    std::cout << "\t\"section_name\": {" << std::endl;
    std::cout << "\t\t\"certDetails\": {" << std::endl;
    std::cout << "\t\t\t...cert details can be defined here..." << std::endl;
    std::cout << "\t\t}," << std::endl;
    std::cout << "\t\t\"keyUsage\": {" << std::endl;
    std::cout << "\t\t\t...key usage can be defined here..." << std::endl;
    std::cout << "\t\t}," << std::endl;
    std::cout << "\t\t\"basicConstraints\": {" << std::endl;
    std::cout << "\t\t\t...basic constraints can be defined here..." << std::endl;
    std::cout << "\t\t}," << std::endl;
    std::cout << "\t\t\"certificateValiditySeconds\": SecondsAsInt," << std::endl;
    std::cout << "\t\t\"notBeforeAsn1\": \"200714085617Z\"," << std::endl;
    std::cout << "\t\t\"digestType\": \"SHA512\"" << std::endl;
    std::cout << "\t}" << std::endl;
    std::cout << "}" << std::endl;
}

void printCertDetailsHelp()
{
    std::cout << "-------Certificate create options--------" << std::endl;
    std::cout << "Cert Details options (all values are strings):" << std::endl;
    std::cout << "\tcommonName" << std::endl;
    std::cout << "\tcountryName" << std::endl;
    std::cout << "\tlocalityName" << std::endl;
    std::cout << "\tstateOrProvinceName" << std::endl;
    std::cout << "\torganizationName" << std::endl;
    std::cout << "\torganizationalUnitName" << std::endl;
    std::cout << "\tpkcs9EmailAddress" << std::endl;
    std::cout << "\tgivenName" << std::endl;
    std::cout << "\tuserId" << std::endl;
    std::cout << "\ttitle" << std::endl;
    std::cout << "-----------------------------------------" << std::endl;
}

void printSignDetailsHelp()
{
    std::cout << "-------------CSR sign options------------" << std::endl;
    std::cout << "Key Usage options (all values are json-booleans):" <<std::endl;
    std::cout << "\tdecipherOnly" << std::endl;
    std::cout << "\tencipherOnly" << std::endl;
    std::cout << "\tcRLSign" << std::endl;
    std::cout << "\tkeyCertSign" << std::endl;
    std::cout << "\tkeyAgreement" << std::endl;
    std::cout << "\tdataEncipherment" << std::endl;
    std::cout << "\tnonRepudiation" << std::endl;
    std::cout << "\tdigitalSignature" << std::endl;
    std::cout << std::endl;
    std::cout << "Basic Contraings options:" <<std::endl;
    std::cout << "\tisCA [boolean]" << std::endl;
    std::cout << "\tpathlength [integer]" << std::endl;
    std::cout << std::endl;
    std::cout << "Miscellaneous options:" << std::endl;
    std::cout << "\tcertificateValiditySeconds [integer] (Time in seconds. Starting from notBeforeAsn1" << std::endl;
    std::cout << "\tnotBeforeAsn1 [ASN1 UTC Time format string] (If not set the current time is used)" << std::endl;
    std::cout << "\tdigestType [string] (Available digests: SHA256, SHA384, SHA512, SHA3-256, SHA3-384, SHA3-512) "
              << std::endl;
    std::cout << "-----------------------------------------" << std::endl;
}

void printConfigHelp()
{
    std::cout << "The configuration file contains information for signing certificates or creating CSRs" << std::endl;
    std::cout << "These information are ordered in sections. Each section can contain information for signing "
                 "certificates or creating CSRs" << std::endl;
    std::cout << "A special case is the creation of a root CA. This section needs to contain data for the certificate "
                 "creation and for the signing." << std::endl;
    std::cout << "The certDetails section is needed for creatings CSRs. The other sections are needed for "
                 "signing CSRs."<< std::endl << std::endl;
    std::cout << "The configuration file looks like follows: " << std::endl;
    printSectionDescription();
    std::cout << std::endl;
    printCertDetailsHelp();
    std::cout << std::endl;
    printSignDetailsHelp();
}

void parseCommandlineArgs(int argc, char *argv[], po::variables_map &vm)
{
    po::options_description caOpts("Options for the certificate authority");
    caOpts.add_options()
            ("sign", "Sign a certificate signing request (CSR)")
            ("create", "Create a root certificate authority. This will return a self signed certificate")
            ("config-file", po::value<std::string>(), "The config file holding the configuration for the CA and "
                                                      "intermediate CAs")
            ("config-section", po::value<std::string>(), "Config section that shall be used (e.g. ca, rootca, ...)")
            ("config-help", "Prints a help for the configuration file.")
            ("private-key", po::value<std::string>(), ("Path to the private key."))
            ("private-key-password", po::value<std::string>()->default_value(""), "Optional: password for the private "
                                                                                  "key")
            ("output-path", po::value<std::string>(), "Write the certificate to a file. Define the path here. "
                                                      "Otherwise the certificate is written to stdout")
            ("verbose", "Verbose output")
            ;

    po::options_description signOpts("Options for signing a CSR");
    signOpts.add_options()
            ("ca-cert", po::value<std::string>(), "Path to the CA certificate")
            ("csr", po::value<std::string>(), "Path to the CSR which shall be signed. Only PEM format is supported.");

    po::options_description cmdlineOptions;
    cmdlineOptions.add(get_generic_options_description())
                  .add(caOpts)
                  .add(signOpts)
            ;

    succeedOrExit(!parseCommandLineOptions(cmdlineOptions, vm, argc, argv), "Failure parsing command line.");

    if (vm.count("help") || argc == 1) {
        std::cerr << cmdlineOptions << "\n";
        exit(EXIT_SUCCESS);
    }

    if (vm.count("config-help")) {
        printConfigHelp();
        exit(EXIT_SUCCESS);
    }

    succeedOrExit(!vm.count("config-file"), "You need to specify a config file (--config-file)");
    succeedOrExit(!vm.count("config-section"), "You must specify a config section, which shall be used. "
                                               "(--config-section");
    succeedOrExit(!(vm.count("create") xor vm.count("sign")), "You must either select sign or create");
    succeedOrExit(!(vm.count("private-key")), "You need a private key for signing and for root CA certificate "
                                              "creation. (--private-key)");

    if (vm.count("sign")) {
        succeedOrExit(!vm.count("ca-cert"), "You need to specify a CA certificate. (--ca-cert)");
        succeedOrExit(!vm.count("csr"), "You need to specify a CSR which shall be signed. (--csr)");
    }
}

void parseCaData(struct CaData &caData)
{
    auto vm = *caData.vm.get();
    auto propertyTree = *caData.config.get();
    const std::string treePrefix(vm["config-section"].as<std::string>());

    caData.signParams = getSigningParams(propertyTree, treePrefix);
    caData.privKey = std::make_shared<AsymmetricPrivateKey>(loadPrivkeyFromFile(vm["private-key"].as<std::string>(),
                vm["private-key-password"].as<std::string>()));
}

void parseCreateCertificateData(struct CaData &caData)
{
    auto vm = *caData.vm.get();
    auto propertyTree = *caData.config.get();
    const std::string treePrefix(vm["config-section"].as<std::string>());

    parseCaData(caData);
    caData.certDetails = getCertDetails(propertyTree.get_child(treePrefix + ".certDetails"));
}

void parseSignCsrData(struct CaData &caData)
{
    auto vm = *caData.vm;
    auto propertyTree = *caData.config.get();
    const std::string treePrefix(vm["config-section"].as<std::string>());

    parseCaData(caData);
    caData.rootCert = std::make_shared<X509Certificate>(loadCertFromFile(vm["ca-cert"].as<std::string>()));
    caData.csr = std::make_shared<CertificateSigningRequest>(CertificateSigningRequest::fromPEMFile(
                                                                 vm["csr"].as<std::string>()));
}

int main(int argc, char *argv[])
{
    auto vm_ptr = std::make_shared<po::variables_map>();
    auto config = std::make_shared<pt::ptree>();
    parseCommandlineArgs(argc, argv, *vm_ptr.get());
    readJsonConfigFile(*config.get(), *vm_ptr.get());
    auto vm = *(vm_ptr.get());
    if (vm.count("verbose")) {
            printAllParsedOptions(vm);
            printTree(*config.get(), 0);
    }

    struct CaData caData(config, vm_ptr);
    parseCaData(caData);

    std::shared_ptr<X509Certificate> cert;

    if (vm.count("create")) {
        try {
            // Create a root certificate
            parseCreateCertificateData(caData);
            cert = createRootCertificate(caData);
        }  catch (MoCOCrWException &e) {
            std::cerr << "Failure creating root CA: ";
            std::cerr << e.what() << std::endl;
        }
    } else {
        // sign a csr
        parseSignCsrData(caData);
        cert = signCsr(caData);
    }

    if (vm.count("output-path")) {
        auto path = vm["output-path"].as<std::string>();
        writePemToFile(cert->toPEM(), path);
    } else {
        std::cout << cert->toPEM() << std::endl;
    }

    return 0;
}
