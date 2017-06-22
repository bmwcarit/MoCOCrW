/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
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

#define ERROR_STRING(msg) \
    (boost::format{"%s: %s"} % BOOST_CURRENT_FUNCTION % (msg)  ).str()
}  //::mococrw
