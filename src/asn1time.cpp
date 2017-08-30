/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */

#include "mococrw/asn1time.h"

using namespace std::string_literals;

namespace mococrw
{
using namespace openssl;

Asn1Time::Asn1Time(openssl::SSL_ASN1_TIME_Ptr &&ptr)
    : _asn1Time{std::move(ptr)}
{
}

Asn1Time::Asn1Time(const ASN1_TIME *t)
    : _asn1Time{_ASN1_TIME_copy(t)}
{
}

Asn1Time Asn1Time::fromString(const std::string &asn1TimeStr)
{
    auto asn1Time = _ASN1_TIME_new();
    _ASN1_TIME_set_string(asn1Time.get(), asn1TimeStr.c_str());
    return Asn1Time{std::move(asn1Time)};
}

Asn1Time Asn1Time::fromTimePoint(std::chrono::system_clock::time_point tp)
{
    return Asn1Time{_ASN1_TIME_from_time_t(std::chrono::system_clock::to_time_t(tp))};
}

Asn1Time Asn1Time::fromTimeT(std::time_t tt)
{
    return Asn1Time{_ASN1_TIME_from_time_t(tt)};
}

std::chrono::system_clock::time_point Asn1Time::toTimePoint() const
{
    return _asn1TimeToTimePoint(internal());
}

bool Asn1Time::operator==(const Asn1Time &rhs) const
{
    return timeCompare(*this, rhs) == TimeDifference::T1_EQUAL_T2;
}

bool Asn1Time::operator!=(const Asn1Time &rhs) const
{
    return !(*this == rhs);
}

bool Asn1Time::operator<(const Asn1Time &rhs) const
{
    return timeCompare(*this, rhs) == TimeDifference::T1_SMALLER_T2;
}

bool Asn1Time::operator>(const Asn1Time &rhs) const
{
    return !(*this <= rhs);
}

bool Asn1Time::operator<=(const Asn1Time &rhs) const
{
    auto td = timeCompare(*this, rhs);
    return td == TimeDifference::T1_SMALLER_T2 || td == TimeDifference::T1_EQUAL_T2;
}

bool Asn1Time::operator>=(const Asn1Time &rhs) const
{
    return !(*this < rhs);
}

Asn1Time::TimeDifference Asn1Time::timeCompare(const Asn1Time &t1, const Asn1Time &t2)
{
    int days, seconds;
    _ASN1_TIME_diff(&days, &seconds, t1.internal(), t2.internal());

    if ((days < 0 && seconds > 0)
            || (days > 0 && seconds < 0)) {
        throw OpenSSLException("OpenSSL violates API convention");
    }

    if (days == 0 && seconds == 0) {
        return TimeDifference::T1_EQUAL_T2;
    } else if (seconds > 0 || days > 0) {
        return TimeDifference::T1_SMALLER_T2;
    } else {
        return TimeDifference::T1_GREATER_T2;
    }
}

}
