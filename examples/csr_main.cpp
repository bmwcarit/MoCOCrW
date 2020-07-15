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
#include <boost/program_options.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "mococrw/private/parsingUtils.h"
#include "mococrw/private/IOUtils.h"

#include "csr_example.h"

namespace po = boost::program_options;
namespace pt = boost::property_tree;
using namespace mococrw;

void parseCommandlineArgs(int argc, char *argv[], po::variables_map &vm)
{
    po::options_description csrOpts("Options for the certificate authority");

    csrOpts.add_options()
            ("config-file", po::value<std::string>(), "The config file holding the configuration for the CA and "
                                                      "intermediate CAs")
            ("config-section", po::value<std::string>(), "Config section that shall be used (e.g. ca, rootca, ...)")
            ("private-key", po::value<std::string>(), ("Path to the private key."))
            ("private-key-password", po::value<std::string>()->default_value(""), "Optional: password for the private "
                                                                                  "key")
            ("output-path", po::value<std::string>(), "Write the certificate to a file. Define the path here. "
                                                      "Otherwise the certificate is written to stdout")
            ("verbose", "Verbose output")
            ;

    po::options_description cmdlineOptions;
    cmdlineOptions.add(get_generic_options_description())
                  .add(csrOpts)
            ;

    succeedOrExit(!parseCommandLineOptions(cmdlineOptions, vm, argc, argv), "Failure parsing command line.");

    if (vm.count("help") || argc == 1) {
        std::cerr << cmdlineOptions << "\n";
        exit(EXIT_SUCCESS);
    }
    succeedOrExit(!vm.count("config-file"), "You need to specify a config file (--config-file)");
    succeedOrExit(!vm.count("config-section"), "You must specify a config section, which shall be used. "
                                               "(--config-section");
    succeedOrExit(!(vm.count("private-key")), "You need a private key for signing and for root CA certificate "
                                              "creation. (--private-key)");

}

void parseCsrData(struct CsrData &csrData)
{
    auto vm = *csrData.vm.get();
    auto propertyTree = *csrData.config.get();
    const std::string treePrefix(vm["config-section"].as<std::string>());

    csrData.certDetails = getCertDetails(propertyTree.get_child(treePrefix + ".certDetails"));
    csrData.privKey = std::make_shared<AsymmetricPrivateKey>(loadPrivkeyFromFile(vm["private-key"].as<std::string>(),
                                                             vm["private-key-password"].as<std::string>()));
    csrData.digestType = getDigestType(propertyTree.get(treePrefix + ".digestType", ""));;
}

int main(int argc, char *argv[])
{
    auto vm_ptr = std::make_shared<po::variables_map>();
    auto config = std::make_shared<pt::ptree>();
    parseCommandlineArgs(argc, argv, *vm_ptr.get());
    readJsonConfigFile(*config.get(), *vm_ptr.get());
    auto vm = *vm_ptr.get();
    if (vm.count("verbose")) {
            printAllParsedOptions(vm);
            printTree(*config.get(), 0);
    }
    struct CsrData csrData(config, vm_ptr);
    parseCsrData(csrData);

    auto csr = createSigningRequest(csrData);

    std::cout << csr->toPEM() << std::endl;

    return 0;

}
