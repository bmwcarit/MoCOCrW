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
    Asn1Time operator+(const Seconds &d) const;

    /**
     * @brief Returns a duplicate of this Asn1Time that is decreased by the given duration.
     * @param d the duration by which this time should be decreased
     * @return the calculated Asn1Time
     * @throws MoCOCrWException if the resulting time would be outside of the years 1900-9999
     */
    Asn1Time operator-(const Seconds &d) const;

    /**
     * @brief Returns the difference between this Asn1Time and the given one.
     * @param rhs the other Asn1Time to which the difference is calculated
     * @return a difference that is guaranteed to have rhs + diff = this
     */
    Seconds operator-(const Asn1Time &rhs) const;

    /**
     * @brief Returns the equivalent of this Asn1Time as a time_point.
     * @throws OpenSSLException if the resulting time_point would be out of bounds.
     * @return the calculated time_point
     */
    std::chrono::system_clock::time_point toTimePoint() const;

    /**
     * @brief Returns the equivalent of this Asn1Time as a time_t.
     * @throws OpenSSLException if the resulting time_t would be out of bounds.
     * @return the calculated time_t
     */
    std::time_t toTimeT() const;

    /**
     * @brief Returns the string representation of this Asn1Time.
     *        The result can be parsed again to an Asn1Time.Seconds
     * @see fromString()
     * @return A string respresentation of the Asn1Time, either ASN1_GENERALIZEDTIME or ASN1_UTCTIME
     *         (see fromString() for the definitions of these)
     */
    std::string toString() const;

    const ASN1_TIME *internal() const { return _asn1Time.get(); }
    ASN1_TIME *internal() { return _asn1Time.get(); }

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

}  // namespace mococrw
