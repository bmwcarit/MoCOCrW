#include <iostream>
#include <unordered_map>
#include <string>

#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/exception/diagnostic_information.hpp>

#include <mococrw/x509.h>
#include <mococrw/key_usage.h>
#include <mococrw/distinguished_name.h>
#include <mococrw/sign_params.h>
#include <mococrw/basic_constraints.h>
#include <mococrw/ca.h>
#include <mococrw/key.h>

#include "common.h"
#include "IOUtils.h"
#include "parsingUtils.h"

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include <set>
#include <exception>

namespace po = boost::program_options;
namespace pt = boost::property_tree;
using namespace mococrw;

void printAllParsedOptions(const po::variables_map &vm)
{
    for (const auto& it : vm) {
        std::cout << it.first.c_str() << " ";
        auto& value = it.second.value();
        if (auto v = boost::any_cast<uint32_t>(&value))
            std::cout << *v;
        else if (auto v = boost::any_cast<std::string>(&value))
            std::cout << *v;
        else if (auto v = boost::any_cast<bool>(&value)) {
            if (*v == true)
                std::cout << "True";
            else if (*v == false)
                std::cout << "False";
            else
                std::cout << "error on boolean";
        } else
            std::cout << "error";
        std::cout << std::endl;
    }
}

std::string indent(int level) {
    std::string s;
    for (int i=0; i<level; i++) s += "  ";
    return s;
}

void printTree (const pt::ptree &pt, int level) {
    if (pt.empty()) {
        std::cerr << "\""<< pt.data()<< "\"";
    }

    else {
        if (level) std::cerr << std::endl;

        std::cerr << indent(level) << "{" << std::endl;

        for (pt::ptree::const_iterator pos = pt.begin(); pos != pt.end();) {
            std::cerr << indent(level+1) << "\"" << pos->first << "\": ";

            printTree(pos->second, level + 1);
            ++pos;
            if (pos != pt.end()) {
                std::cerr << ",";
            }
            std::cerr << std::endl;
        }
        std::cerr << indent(level) << "}" << std::endl;
    }
}

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
    std::cout << std::endl;
    printTree(keyUsageSubTree, 1);

    auto keyUsageBuilder = KeyUsageExtension::Builder{};
    addKeyUsageIfTrue(decipherOnly, "decipherOnly");
    addKeyUsageIfTrue(encipherOnly, "encipherOnly");
    addKeyUsageIfTrue(cRLSign, "cRLSign");
    addKeyUsageIfTrue(keyCertSign, "keyCertSign");
    addKeyUsageIfTrue(keyAgreement, "keyAgreement");
    addKeyUsageIfTrue(dataEncipherment, "dataEncipherment");
    addKeyUsageIfTrue(nonRepudiation, "nonRepudiation");
    addKeyUsageIfTrue(digitalSignature, "digitalSignature");
    return std::make_shared<KeyUsageExtension>(keyUsageBuilder.build());
}
#undef addKeyUsageIfTrue

template <class Builder, class Type>
Builder invokeIfNotEmpty(Builder b, std::function<Builder ( Type )> func, Type val)
{
    if (val.empty()) {
        return b;
    }
    return func(val);
}

#define addCertDetailIfSet(func, str)  \
    detailsBuilder = invokeIfNotEmpty<DistinguishedName::Builder, std::string>( \
        detailsBuilder, \
        std::bind(&DistinguishedName::Builder::func<std::string>, detailsBuilder, std::placeholders::_1), \
        certDetails.get(str, "") \
    )

std::shared_ptr<DistinguishedName> getCertDetails(pt::ptree certDetails)
{
    std::cout << std::endl;
    printTree(certDetails, 1);
    auto detailsBuilder = DistinguishedName::Builder{};

    addCertDetailIfSet(commonName, "commonName");
    addCertDetailIfSet(countryName, "countryName");
    addCertDetailIfSet(localityName, "localityName");
    addCertDetailIfSet(stateOrProvinceName, "stateOrProvinceName");
    addCertDetailIfSet(organizationName, "organizationName");
    addCertDetailIfSet(organizationalUnitName, "organizationalUnitName");
    addCertDetailIfSet(pkcs9EmailAddress, "pkcs9EmailAddress");
    addCertDetailIfSet(givenName, "givenName");
    addCertDetailIfSet(userId, "title");
    addCertDetailIfSet(title, "userId");

    return std::make_shared<DistinguishedName>(detailsBuilder.build());
}
#undef addCertDetailIfSet


std::shared_ptr<CertificateAuthority> getCa(pt::ptree &propertyTree, const po::variables_map &vm)
{
    std::string filePath = vm["config-file"].as<std::string>();
    pt::json_parser::read_json(filePath, propertyTree);
    printTree(propertyTree, 0);

    std::string treePrefix = vm["config-section"].as<std::string>();

    auto keyUsageSubTree = propertyTree.get_child(treePrefix + ".keyUsage");
    auto caKeyUsage = getKeyUsageExtension(keyUsageSubTree);

    auto certDetailsSubTree = propertyTree.get_child(treePrefix + ".certDetails");
    auto caCertDetails = getCertDetails(certDetailsSubTree);

    auto basiConstraintsSubTree = propertyTree.get_child(treePrefix + ".basicConstraints");
    auto caBasicConstraints = getBasicConstraintsExtension(basiConstraintsSubTree);

    auto now = Asn1Time::now();
    try {
        auto notBefore = Asn1Time::fromString(propertyTree.get(treePrefix + ".notBeforeAsn1", ""));
    }  catch (openssl::OpenSSLException &e) {
        std::cerr << "Failure parsing notBeforeAsn1 time" << std::endl;
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    auto privKey = loadPrivkeyFromFile(vm["private-key"].as<std::string>(),
                vm["private-key-password"].as<std::string>());

    auto _caSignParams = CertificateSigningParameters::Builder{}
            .certificateValidity(Asn1Time::Seconds(120))
            .digestType(openssl::DigestTypes::SHA256)
            .addExtension(*caBasicConstraints)
            .addExtension(*caKeyUsage)
            .build();

    auto rootCert = CertificateAuthority::createRootCertificate(
            privKey,
            *caCertDetails,
            0,
            _caSignParams);

    auto _signParams = CertificateSigningParameters::Builder{}.build();

    return std::make_shared<CertificateAuthority>(_signParams, 1, rootCert, privKey);
}

void parseCommandlineArgs(int argc, char *argv[], po::variables_map &vm)
{
    po::options_description caOpts("Options for the certificate authority");
    caOpts.add_options()
            ("sign", "Sign a certificate signing request (CSR)")
            ("create", "Create a certificate authority (CA). This will return a self signed certificate")
            ("config-file", po::value<std::string>(), "The config file holding the configuration for the CA and "
                                                      "intermediate CAs")
            ("config-section", po::value<std::string>(), "Config section that shall be used (e.g. ca, rootca, ...)")
            ;

    po::options_description signOpts("Options for the certificate authority");
    signOpts.add_options()
            ("private-key", po::value<std::string>(), "Path to the private key of the CA")
            ("private-key-password", po::value<std::string>()->default_value(""), "Optional: password for the private "
                                                                                  "key")
            ("ca-cert", po::value<std::string>(), "Path to the CA certificate")
            ("csr", po::value<std::string>(), "Path to the CSR which shall be signed")
            ;

    po::options_description createOpts("Options for creating a certificate");
    createOpts.add_options()
            ("private-key", po::value<std::string>(), ("Path to the private key"))
            ("private-key-password", po::value<std::string>()->default_value(""), "Optional: password for the private "
                                                                                  "key")
            ;

    po::options_description cmdlineOptions;
    cmdlineOptions.add(get_generic_options_description())
                  .add(caOpts)
                  .add(signOpts)
            ;

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
        std::string info = boost::diagnostic_information(e);
        std::cerr << "Caught boost exception during parsing. Please check your input!" << std::endl;
        std::cerr << info << std::endl;
        exit(EXIT_FAILURE);
    }
    po::notify(vm);

    if (vm.count("help") || argc == 1) {
        std::cerr << cmdlineOptions << "\n";
        exit(EXIT_SUCCESS);
    }

    succeedOrExit(!vm.count("config-file"), "You need to specify a config file");

}

int main(int argc, char *argv[])
{
    po::variables_map vm;
    pt::ptree propertyTree;
    parseCommandlineArgs(argc, argv, vm);
    getCa(propertyTree, vm);
    printAllParsedOptions(vm);

    return 0;
}
