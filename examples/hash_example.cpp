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
void parseCommandlineArgs(int argc, char *argv[], po::variables_map &vm)
{
    po::options_description genericHashOptions("Generic options for hash value calculation");
    genericHashOptions.add_options()
        ("message", po::value<std::string>(), "Message to be signed or verified in hex form (with or without 0x "
                                              "prepended)")
        ("hash-algo", po::value<std::string>(),"The hash algorith used for digest calculation. Available: SHA256, "
                                               "SHA384, SHA512, SHA3-256, SHA3-384, SHA3-512"
        )
    ;

    po::options_description cmdlineOptions;
    cmdlineOptions.add(get_generic_options_description())
                  .add(genericHashOptions);

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

    succeedOrExit(!vm.count("message"), "You need to specify a message");
    succeedOrExit(!vm.count("hash-algo"), "You need to specify a hash algorithm");

}

void calculateHashSum(const po::variables_map &vm)
{
    openssl::DigestTypes digest = getDigest(vm["hash-algo"].as<std::string>());
    printVerbose("Using digest algorithm " << vm["hash-algo"].as<std::string>());
    auto hash = Hash::fromDigestType(digest);

    auto hashValue = hash.update(vm["message"].as<std::string>()).digest();

    std::cout << utility::toHex(hashValue) << std::endl;
}

int main(int argc, char *argv[])
{
    po::variables_map vm;
    parseCommandlineArgs(argc, argv, vm);
    calculateHashSum(vm);
    return 0;
}
