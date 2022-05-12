/*
 * #%L
 * %%
 * Copyright (C) 2018 BMW Car IT GmbH
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

#include <string>
#include <vector>

#include <boost/format.hpp>

#include "mococrw/error.h"

namespace mococrw
{
namespace util
{
/**
 * Splits a string of concatenated PEM elements into a list of PEMs.
 * If not existing, this also adds a line break after the start element and before the end element
 * of each PEM since this is usually necessary for OpenSSL to parse the resulting PEMs.
 * @param pemChain the concatenated PEMs
 * @param beginMarker the start element (typically -----BEGIN ...-----)
 * @param endMarker the end element (typically -----END ...-----)
 * @return a vector with all PEMs, in the same order that they appeared in the chain.
 * @throw MoCOCrWException if the string didn't contain a list of PEMs.
 */
inline std::vector<std::string> splitPEMChain(const std::string& pemChain,
                                              const std::string& beginMarker,
                                              const std::string& endMarker)
{
    std::string::size_type pos = 0;
    std::size_t index = 0;
    std::vector<std::string> pemList;

    while (pos < pemChain.size()) {
        auto nextBeginPos = pemChain.find(beginMarker, pos);
        if (nextBeginPos == std::string::npos) {
            // This is an error case if anything else than whitespace is in the rest of the string
            // after the last PEM element.
            if (pemChain.substr(pos).find_first_not_of(" \r\n\t") != std::string::npos) {
                throw MoCOCrWException("PEM Chain invalid. Invalid characters at end of chain");
            }
            break;
        }

        if (nextBeginPos != pos) {
            // verify that only white spaces are in between. Otherwise the format is broken
            if (pemChain.substr(pos, nextBeginPos - pos).find_first_not_of(" \r\n\t") !=
                std::string::npos) {
                auto formatter =
                        boost::format("PEM Chain invalid. Invalid characters before element %d");
                formatter % index;
                throw MoCOCrWException(formatter.str());
            }
        }
        auto encodedPemBeginPos =
                pemChain.find_first_not_of(" \r\n\t", nextBeginPos + beginMarker.size());

        auto nextEndPos = pemChain.find(endMarker, encodedPemBeginPos);
        if (nextEndPos == std::string::npos) {
            auto formatter = boost::format("PEM chain invalid. Element %d has no end marker");
            formatter % index;
            throw MoCOCrWException(formatter.str());
        }
        auto encodedPem = pemChain.substr(encodedPemBeginPos, nextEndPos - encodedPemBeginPos);
        auto lastNonWhitespace = encodedPem.find_last_not_of(" \r\n\t");
        if (lastNonWhitespace == std::string::npos) {
            auto formatter = boost::format("PEM chain invalid. Element %d appears to be empty");
            formatter % index;
            throw MoCOCrWException(formatter.str());
        }
        // remove trailing whitespaces from PEM content
        encodedPem.erase(lastNonWhitespace + 1);
        // OpenSSL expects a newline after the begin marker and before the end marker
        // so we make sure that there is one...
        auto certificatePem =
                boost::str(boost::format("%1%\n%2%\n%3%") % beginMarker % encodedPem % endMarker);

        pemList.emplace_back(std::move(certificatePem));
        pos = nextEndPos + endMarker.size();
        index++;
    }

    return pemList;
}

}  // namespace util

}  // namespace mococrw
