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

#include <memory>
#include <vector>

#include <openssl/crypto.h>

#include "mococrw/error.h"

namespace mococrw
{
namespace utility
{

template <class T>
using SharedPtrTypeFromUniquePtr = std::shared_ptr<typename T::element_type>;

std::string toHex(const std::vector<uint8_t> &data);

std::vector<uint8_t> fromHex(const std::string &hexData);

std::vector<uint8_t> cryptoRandomBytes(size_t length);

template<typename T>
void vectorCleanse(std::vector<T> &vec)
{
    OPENSSL_cleanse(vec.data(), vec.size() * sizeof(T));
}

/**
 * RAII wrapper that executes a lambda on destruction
 */

class Finally {
public:
    /**
     * Create a new finally object, which will run the given function when it
     * goes out of scope.
     *
     * @param[in] func Function to run on destruction.
     */
    template<class T>
    Finally(T&& func)
        : _func(std::forward<T>(func)) {}

    Finally(const Finally& other) = delete;
    Finally(Finally&& other) = delete;
    Finally& operator=(const Finally& other) = delete;
    Finally& operator=(Finally&& other) = delete;

    ~Finally() {
        if (_func) {
            _func();
        }
    }

private:
    /// Function to be called on shutdown.
    std::function<void()> _func;
};


}  //::utility
}  //::mococrw
