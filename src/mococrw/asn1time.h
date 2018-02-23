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
    /**
     * @brief Create an Asn1Time from a string representation
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

    /**
     * @brief Returns the current system time.
     */
    static Asn1Time now();

    /**
     * @brief Returns the greatest time that Asn1Time supports: 31.12.9999, 23:59:59.
     */
    static Asn1Time max();

    /**
     * @brief Returns the smallest time that Asn1Time supports: 01.01.0000, 00:00:00.
     */
    static Asn1Time min();

    /**
     * A seconds-period duration that uses a 64 bit integer for storage.
     * This covers the complete range of valid ASN1 time differences.
     */
    using Seconds = std::chrono::duration<int64_t>;

    /**
     * @brief Returns a duplicate of this Asn1Time that is increased by the given duration.
     * @param d the duration by which this time should be increased
     * @return the calculated Asn1Time
     * @throws MoCOCrWException if the resulting time would be outside of the years 1900-9999
     */
    Asn1Time operator+(const Seconds& d) const;

    /**
     * @brief Returns a duplicate of this Asn1Time that is decreased by the given duration.
     * @param d the duration by which this time should be decreased
     * @return the calculated Asn1Time
     * @throws MoCOCrWException if the resulting time would be outside of the years 1900-9999
     */
    Asn1Time operator-(const Seconds& d) const;

    /**
     * @brief Returns the difference between this Asn1Time and the given one.
     * @param rhs the other Asn1Time to which the difference is calculated
     * @return a difference that is guaranteed to have rhs + diff = this
     */
    Seconds operator-(const Asn1Time& rhs) const;

    std::chrono::system_clock::time_point toTimePoint() const;

    /**
     * @brief Returns the string representation of this Asn1Time.
     *        The result can be parsed again to an Asn1Time.Seconds
     * @see fromString()
     * @return A string respresentation of the Asn1Time, either ASN1_GENERALIZEDTIME or ASN1_UTCTIME
     *         (see fromString() for the definitions of these)
     */
    std::string toString() const;

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
};

}
