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

#include <boost/current_function.hpp>
#include <boost/format.hpp>

namespace mococrw
{
class MoCOCrWException : public std::exception
{
public:
    template <class StringType>
    explicit MoCOCrWException(StringType &&msg) : _msg{std::forward<StringType>(msg)}
    {
    }
    const char *what() const noexcept override { return _msg.c_str(); }

private:
    const std::string _msg;
};

#define ERROR_STRING(msg) (boost::format{"%s: %s"} % BOOST_CURRENT_FUNCTION % (msg)).str()
}  // namespace mococrw
