/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#pragma once

#include "mococrw/openssl_wrap.h"

namespace mococrw
{

class Asn1Time
{
public:
    /* @brief Create an Asn1Time from a string representation
     *
     * Creates an Asn1Time object from a string representation of
     * ASN1_GENERALIZEDTIME (YYYYMMDDHHMMSSZ) or ASN1_UTCTIME
     * (YYMMDDHHMMSSZ).
     *
     * @throw OpenSSLException if the format of the string is invalid
     */
    static Asn1Time fromString(const std::string &asn1TimeStr);
    static Asn1Time fromTimePoint(std::chrono::system_clock::time_point tp);
    static Asn1Time fromTimeT(std::time_t tt);

    std::chrono::system_clock::time_point toTimePoint() const;

    const ASN1_TIME* internal() const { return _asn1Time.get(); }
    ASN1_TIME* internal() { return _asn1Time.get(); }

    bool operator==(const Asn1Time &rhs) const;
    bool operator!=(const Asn1Time &rhs) const;
    bool operator<(const Asn1Time &rhs) const;
    bool operator>(const Asn1Time &rhs) const;
    bool operator<=(const Asn1Time &rhs) const;
    bool operator>=(const Asn1Time &rhs) const;

    explicit Asn1Time(openssl::SSL_ASN1_TIME_Ptr &&ptr);
    explicit Asn1Time(const ASN1_TIME *t);
private:
    openssl::SSL_ASN1_TIME_SharedPtr _asn1Time;

    enum class TimeDifference
    {
        T1_SMALLER_T2,
        T1_EQUAL_T2,
        T1_GREATER_T2
    };
    static TimeDifference timeCompare(const Asn1Time &t1, const Asn1Time &t2);
};

}
