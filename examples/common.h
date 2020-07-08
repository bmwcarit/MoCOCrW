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
#pragma once

#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>

#include <boost/algorithm/string.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/program_options.hpp>
#include <boost/property_tree/ptree.hpp>

#include <mococrw/hash.h>


#define succeedOrExit(condition, ...) do { \
        if (condition) { \
            std::cerr << __VA_ARGS__ << std::endl; \
            exit(EXIT_FAILURE); \
        } \
    } while(0)

namespace po = boost::program_options;
namespace pt = boost::property_tree;

po::options_description get_generic_options_description()
{
    po::options_description generic("Common options");
    generic.add_options()
            ("help,h", "This help")
            ;
    return generic;
}

po::options_description get_encryption_options_description()
{
    po::options_description desc("Options for asymmetric/symmetric encryption and decryption");
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
    if (!(vm.count("decrypt") ^ vm.count("encrypt"))) {
        std::cerr << "You can either decrypt or encrypt the data" << std::endl;
        return false;
    }

    if (vm.count("verbose") && vm.count("chaining")) {
        // Either verbose or chaining can be selected
        std::cerr << "You cannot choose chaining and verbose at the same time." << std::endl;
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
    if (!(vm.count("sign") ^ vm.count("verify"))) {
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
        if (!(vm.count("public-key") ^ vm.count("cert"))) {
            return false;
        }
    }
    return true;
}

bool parseCommandLineOptions(const po::options_description &cmdlineOptions, po::variables_map &vm,
                             int argc, char *argv[])
{
    try {
        po::store(po::parse_command_line(argc, argv, cmdlineOptions), vm);
    } catch (boost::program_options::invalid_command_line_syntax &e) {
        std::cerr << "Failure parsing the input. Please check your input!" << std::endl;
        std::cerr << e.what() << std::endl;
        return false;
    } catch (boost::program_options::invalid_option_value &e) {
        std::cerr << "Got invalid option value (e.g. string for integer). Please check your input!" << std::endl;
        std::cerr << e.what() << std::endl;
        return false;
    } catch (boost::program_options::unknown_option &e) {
        std::cerr << "Unknown option selected: ";
        std::cerr << e.what() << std::endl;
        return false;
    } catch (boost::exception &e) {
        std::string info = boost::diagnostic_information(e);
        std::cerr << "Caught boost exception during parsing. Please check your input!" << std::endl;
        std::cerr << info << std::endl;
        return false;
    }
    po::notify(vm);
    return true;
}

void printAllParsedOptions(const po::variables_map &vm)
{
    for (const auto& it : vm) {
        std::cout << it.first.c_str() << " ";
        auto& value = it.second.value();
        if (auto v = boost::any_cast<uint32_t>(&value)) {
            std::cout << *v;
        } else if (auto v = boost::any_cast<std::string>(&value)) {
            std::cout << *v;
        } else if (auto v = boost::any_cast<bool>(&value)) {
            if (*v == true) {
                std::cout << "True";
            } else {
                std::cout << "False";
            }
        } else {
            std::cout << "error";
        }
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
        std::cout << "\""<< pt.data()<< "\"";
    }

    else {
        if (level) std::cout << std::endl;

        std::cout << indent(level) << "{" << std::endl;

        for (pt::ptree::const_iterator pos = pt.begin(); pos != pt.end();) {
            std::cout << indent(level+1) << "\"" << pos->first << "\": ";

            printTree(pos->second, level + 1);
            ++pos;
            if (pos != pt.end()) {
                std::cout << ",";
            }
            std::cout << std::endl;
        }
        std::cout << indent(level) << "}" << std::endl;
    }
}
