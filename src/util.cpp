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

#include "mococrw/util.h"

#include <iomanip>
#include <sstream>

#include "mococrw/openssl_wrap.h"

namespace mococrw
{
namespace utility
{
std::string toHex(const std::vector<uint8_t> &data)
{
    std::stringstream result;
    for (size_t i = 0; i < data.size(); i++) {
        result << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    return result.str();
}

std::vector<uint8_t> fromHex(const std::string &hexData)
{
    std::vector<uint8_t> binary;
    binary.reserve(hexData.size() / 2);
    size_t startPos = 0;
    if (hexData.rfind("0x") == 0) {
        startPos = 2;
    }
    for (size_t i = startPos; i < hexData.length(); i += 2) {
        auto encodedByte = hexData.substr(i, 2);
        char *endptr;
        errno = 0;
        uint8_t b = (uint8_t)strtoul(encodedByte.c_str(), &endptr, 16);

        if (errno != 0 && b == 0) {
            std::string error_string = "Invalid hex string: ";
            error_string += hexData;
            throw MoCOCrWException(error_string);
        }
        /* From strtoul documentation:
         * "In particular, if *nptr is not '\0' but **endptr is '\0' on return, the entire string is
         * valid." */
        if (!(*encodedByte.c_str() != '\0' && *endptr == '\0')) {
            std::string error_string = "Invalid hex string: ";
            error_string += hexData;
            throw MoCOCrWException(error_string);
        }
        binary.push_back(b);
    }

    return binary;
}

std::vector<uint8_t> cryptoRandomBytes(size_t length)
{
    std::vector<uint8_t> buffer(length);
    openssl::_RAND_bytes(buffer.data(), buffer.size());
    return buffer;
}

void stringCleanse(std::string &str)
{
    // &str[0] is always a valid pointer
    openssl::_OPENSSL_cleanse(&str[0], str.size());
    str.clear();
}

}  // namespace utility
}  // namespace mococrw
