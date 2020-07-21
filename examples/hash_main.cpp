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
#include "hash_example.h"
#include "mococrw/private/parsingUtils.h"


namespace po = boost::program_options;
using namespace mococrw;
void parseCommandlineArgs(int argc, char *argv[], po::variables_map &vm)
{
    po::options_description genericHashOptions("Generic options for hash value calculation");
    genericHashOptions.add_options()
        ("message", po::value<std::string>(), "Message for hash sum calculation in hex form (with or without 0x "
                                              "prepended)")
        ("hash-algo", po::value<std::string>(),"The hash algorith used for digest calculation. Available: SHA256, "
                                               "SHA384, SHA512, SHA3-256, SHA3-384, SHA3-512"
        )
    ;

    po::options_description cmdlineOptions;
    cmdlineOptions.add(get_generic_options_description())
                  .add(genericHashOptions);

    succeedOrExit(!parseCommandLineOptions(cmdlineOptions, vm, argc, argv), "Failure parsing command line.");

    if (vm.count("help") || argc == 1) {
        std::cerr << cmdlineOptions << "\n";
        exit(EXIT_SUCCESS);
    }

    succeedOrExit(!vm.count("message"), "You need to specify a message");
    succeedOrExit(!vm.count("hash-algo"), "You need to specify a hash algorithm");
}

void parseMe(struct HashData &hashData)
{
    auto vm = *hashData.vm.get();
    hashData.digestType = getDigestType(vm["hash-algo"].as<std::string>());
    hashData.message = vm["message"].as<std::string>();
}

int main(int argc, char *argv[])
{
    auto vm = std::make_shared<po::variables_map>();
    parseCommandlineArgs(argc, argv, *vm.get());
    struct HashData hashData(vm);
    parseMe(hashData);

    calculateHashSum(hashData);
    return 0;
}
