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
#include "mococrw/asn1time.h"

#include "mococrw/bio.h"
#include "mococrw/error.h"

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

Asn1Time Asn1Time::now()
{
    return Asn1Time::fromTimePoint(std::chrono::system_clock::now());
}

Asn1Time Asn1Time::min()
{
    return Asn1Time::fromString("00000101000000Z");
}

Asn1Time Asn1Time::max()
{
    return Asn1Time::fromString("99991231235959Z");
}

std::chrono::system_clock::time_point Asn1Time::toTimePoint() const
{
    return _asn1TimeToTimePoint(internal());
}

std::string Asn1Time::toString() const
{
    BioObject bio{BioObject::Types::MEM};
    _ASN1_STRING_print_ex(bio.internal(), internal());
    return bio.flushToString();
}

Asn1Time Asn1Time::operator+(const Asn1Time::Seconds& d) const
{
    /*
     * The fun tale of OpenSSL time continues:
     *
     * Since there is no way to add time to a ASN1_TIME instance, we
     * need to:
     *
     * (1) Create an ASN1_TIME instance corresponding to epoch
     *      Let's call that asn1Epoch
     * (2) Compute the delta between "this" and "asn1Epoch" in days and seconds
     * (3) Add the duration to the delta
     * (4) Create an ASN1_TIME from epoch plus the modified delta
     */
    const time_t epoch = 0;

    auto asn1Epoch = Asn1Time::fromTimeT(epoch);

    //compute the offset between "time" and "asn1Epoch" in days and seconds.
    int days, seconds;
    _ASN1_TIME_diff(&days, &seconds, asn1Epoch.internal(), internal());

    using Chronodays = std::chrono::duration<int, std::ratio<24 * 60 * 60, 1>>;

    // Check if we exceed the maximum number of days we can store
    if (Chronodays(std::numeric_limits<int>::max()) < d
            || Chronodays(std::numeric_limits<int>::min()) > d) {
        throw MoCOCrWException("Duration is too large for Asn1Time differences");
    }

    // Split the duration into days and seconds
    Chronodays durationDays = std::chrono::duration_cast<Chronodays>(d);
    Seconds durationSeconds = d - durationDays;

    // Add the duration seconds to the delta seconds
    // This is safe since both seconds and durationSeconds are smaller than
    // 60*60*24 (1 day) and thus the addition can't overflow 32 bit
    seconds += static_cast<int>(durationSeconds.count());

    // Check if an overflow would occur on day addition
    if ((days > 0 && durationDays.count() > std::numeric_limits<int>::max() - days)
            || (days < 0 && durationDays.count() < std::numeric_limits<int>::min() - days)) {
        throw MoCOCrWException("Duration would overflow Asn1Time");
    }
    // Add the duration days to the delta days
    days += durationDays.count();

    try {
        // And finally convert (epoch + delta) to an ASN1_TIME again
        return Asn1Time{_ASN1_TIME_adj(epoch, days, seconds)};
    } catch (const openssl::OpenSSLException& e) {
        throw MoCOCrWException("Addition leaves Asn1Time range: "s + e.what());
    }
}

Asn1Time Asn1Time::operator-(const Asn1Time::Seconds& d) const
{
    return operator+(-1 * d);
}

Asn1Time::Seconds Asn1Time::operator-(const Asn1Time& other) const
{
    int days;
    int seconds;
    _ASN1_TIME_diff(&days, &seconds, other.internal(), internal());

    // This is a safe operation since hours and Seconds both use int64_t to store their values
    // and the maximum day difference in Asn1Time * 24 doesn't overflow a 32 bit int
    return std::chrono::hours(24 * days) + Seconds(seconds);
}

bool Asn1Time::operator==(const Asn1Time &rhs) const
{
    return *this - rhs == Seconds(0);
}

bool Asn1Time::operator!=(const Asn1Time &rhs) const
{
    return !(*this == rhs);
}

bool Asn1Time::operator<(const Asn1Time &rhs) const
{
    return *this - rhs < Seconds(0);
}

bool Asn1Time::operator>(const Asn1Time &rhs) const
{
    return !(*this <= rhs);
}

bool Asn1Time::operator<=(const Asn1Time &rhs) const
{
    return *this - rhs <= Seconds(0);
}

bool Asn1Time::operator>=(const Asn1Time &rhs) const
{
    return !(*this < rhs);
}

}
