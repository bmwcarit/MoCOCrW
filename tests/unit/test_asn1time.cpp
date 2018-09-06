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
#include <algorithm>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "asn1time.cpp"

using namespace std::string_literals;
using namespace std::chrono_literals;

using namespace mococrw;
using namespace mococrw::openssl;

using testing::Eq;
using testing::Ne;
using testing::Gt;
using testing::Ge;
using testing::Lt;
using testing::Le;

class Asn1TimeTest : public ::testing::Test
{
public:
    void SetUp() override;
protected:
    std::time_t tt_2017_3_27__19_00_38;
    std::chrono::system_clock::time_point tp_2017_3_27__19_00_38;
};

void Asn1TimeTest::SetUp()
{
    /* d = datetime.datetime(2017, 3, 27, 19, 00, 38, tzinfo=datetime.timezone.utc)
     * d.timestamp()
     * 1490641238.0
     */
    tt_2017_3_27__19_00_38 = 1490641238;
    tp_2017_3_27__19_00_38 = std::chrono::system_clock::from_time_t(tt_2017_3_27__19_00_38);
}

TEST_F(Asn1TimeTest, parseFromUTCTime)
{
    auto refFromTimePoint = Asn1Time::fromTimePoint(tp_2017_3_27__19_00_38);
    auto fromUTCTime = Asn1Time::fromString("170327190038Z");
    EXPECT_THAT(fromUTCTime, Eq(refFromTimePoint));
}

TEST_F(Asn1TimeTest, parseFromGeneralizedTime)
{
    auto refFromTimePoint = Asn1Time::fromTimePoint(tp_2017_3_27__19_00_38);
    auto fromGeneralizedTime = Asn1Time::fromString("20170327190038Z");
    EXPECT_THAT(fromGeneralizedTime, Eq(refFromTimePoint));
}

TEST_F(Asn1TimeTest, parseOfInvalidStringThrows)
{
    EXPECT_THROW(auto t = Asn1Time::fromString("20Z"), OpenSSLException);
}

TEST_F(Asn1TimeTest, fromTimePointToTimePointIsIdentical)
{
    auto t = Asn1Time::fromTimePoint(tp_2017_3_27__19_00_38);
    EXPECT_THAT(t.toTimePoint(), Eq(tp_2017_3_27__19_00_38));
}

TEST_F(Asn1TimeTest, fromTimeTToTimeTIsIdentical)
{
    auto t = Asn1Time::fromTimeT(tt_2017_3_27__19_00_38);
    EXPECT_THAT(t.toTimeT(), Eq(tt_2017_3_27__19_00_38));
}

TEST_F(Asn1TimeTest, checkComparisonOperators)
{
    auto year2000 = Asn1Time::fromString("20000101000000Z");
    auto year2020 = Asn1Time::fromString("20200101000000Z");

    auto year2000_copy = year2000;

    EXPECT_THAT(year2000, Eq(year2000_copy));
    EXPECT_THAT(year2000, Ne(year2020));

    EXPECT_THAT(year2000, Le(year2020));
    EXPECT_THAT(year2000, Lt(year2020));
    EXPECT_THAT(year2000, Le(year2000_copy));

    EXPECT_THAT(year2020, Ge(year2000));
    EXPECT_THAT(year2020, Gt(year2000));
    EXPECT_THAT(year2020, Ge(year2020));
}

TEST_F(Asn1TimeTest, conversionOfTimePointMinMaxWorks)
{
    using std::chrono::system_clock;
    const auto tpMin = std::chrono::system_clock::time_point::min();
    const auto tpMax = std::chrono::system_clock::time_point::max();

    auto asn1TpMin = Asn1Time::fromTimePoint(tpMin);
    auto asn1TpMax = Asn1Time::fromTimePoint(tpMax);

    /* Unfortunately the conversion to ASN1Time looses precision to full seconds.
     * As a result, we can only expect it to be equal up to 1s of difference
     */
    EXPECT_THAT(asn1TpMin.toTimePoint(), Ge(tpMin));
    EXPECT_THAT(asn1TpMin.toTimePoint(), Le(tpMin + 1s));
    EXPECT_THAT(asn1TpMax.toTimePoint(), Le(tpMax));
    EXPECT_THAT(asn1TpMax.toTimePoint(), Ge(tpMax - 1s));
}

TEST_F(Asn1TimeTest, fromTimeTWorks)
{
    auto fromUTCTime = Asn1Time::fromString("170327190038Z");
    auto fromTimeT = Asn1Time::fromTimeT(tt_2017_3_27__19_00_38);
    EXPECT_THAT(fromTimeT, Eq(fromUTCTime));
}

TEST_F(Asn1TimeTest, invalidTimePointConversionThrows)
{
    auto year9042 = Asn1Time::fromString("90420101000000Z");
    EXPECT_THROW({
        year9042.toTimePoint();
    }, OpenSSLException);

    auto year0042 = Asn1Time::fromString("00420101000000Z");
    EXPECT_THROW({
        year0042.toTimePoint();
    }, OpenSSLException);
}

TEST_F(Asn1TimeTest, nowTimeIsCorrect)
{
    Asn1Time nowTimeFromApi = Asn1Time::now();
    auto nowTimeFromSystem = std::chrono::system_clock::now();

    //OpenSSL has a precision of 1 second, so we check that
    // -1 < nowApi - nowSystem < 1
    ASSERT_LT(std::chrono::seconds(-1), nowTimeFromApi.toTimePoint() - nowTimeFromSystem);
    ASSERT_LT(nowTimeFromApi.toTimePoint() - nowTimeFromSystem, std::chrono::seconds(1));
}

TEST_F(Asn1TimeTest, addTimeIsCorrect)
{
    auto year2000Day2FromString = Asn1Time::fromString("20000102000000Z");
    auto year2000Day2FromAdd = Asn1Time::fromString("20000101000000Z") + 24h;

    ASSERT_EQ(year2000Day2FromString, year2000Day2FromAdd);
}

TEST_F(Asn1TimeTest, subtractTimeIsCorrect)
{
    auto year2001FromString = Asn1Time::fromString("20010101010000Z");
    auto year2001FromSubtract = Asn1Time::fromString("20020101000000Z")
            - std::chrono::hours(24 * 365 - 1);

    ASSERT_EQ(year2001FromString, year2001FromSubtract);
}

TEST_F(Asn1TimeTest, addingToLargeTimesWorks)
{
    auto year2270FromString = Asn1Time::fromString("22700101000000Z");
    auto year2270FromAdd = Asn1Time::fromString("22690101000000Z") + std::chrono::hours(24 * 365);

    ASSERT_EQ(year2270FromString, year2270FromAdd);
}

TEST_F(Asn1TimeTest, addingLargeDurationsWorks)
{
    auto year2000FromString = Asn1Time::fromString("20000101000000Z");
    auto year2000FromAdd = Asn1Time::fromString("10000101000000Z")
            + std::chrono::hours(365242 * 24);

    ASSERT_EQ(year2000FromString, year2000FromAdd);
}

TEST_F(Asn1TimeTest, subtractingLargeDurationsWorks)
{
    auto year2000FromString = Asn1Time::fromString("20000101000000Z");
    auto year2000FromSubtraction = Asn1Time::fromString("30000101000000Z")
            - std::chrono::hours(365243 * 24);

    ASSERT_EQ(year2000FromString, year2000FromSubtraction);
}

TEST_F(Asn1TimeTest, creatingDifferencesWorks)
{
    auto year2000 = Asn1Time::fromString("20000101000000Z");
    auto year2000Day2Hour1 = Asn1Time::fromString("20000102010000Z");

    ASSERT_EQ(std::chrono::hours(25), year2000Day2Hour1 - year2000);
}

TEST_F(Asn1TimeTest, creatingNegativeDifferencesWorks)
{
    auto year2000 = Asn1Time::fromString("20000101000000Z");
    auto year2010 = Asn1Time::fromString("20100101010101Z");

    ASSERT_EQ(-1 * (year2010 - year2000), year2000 - year2010);
}

TEST_F(Asn1TimeTest, creatingDifferencesDoesNotOverflow)
{
    ASSERT_EQ(std::chrono::seconds(315569519999), Asn1Time::max() - Asn1Time::min());
}

TEST_F(Asn1TimeTest, addingDifferencesDoesNotOverflow)
{
    ASSERT_EQ(Asn1Time::min() + std::chrono::seconds(315569519999), Asn1Time::max());
}

TEST_F(Asn1TimeTest, overflowingAsn1TimeThrows)
{
    ASSERT_THROW(Asn1Time::max() + std::chrono::seconds(1), mococrw::MoCOCrWException);
}

TEST_F(Asn1TimeTest, underflowingAsn1TimeThrows)
{
    ASSERT_THROW(Asn1Time::min() - std::chrono::seconds(1), mococrw::MoCOCrWException);
}

TEST_F(Asn1TimeTest, addingOverflowingDurationThrows)
{
    auto asn1time = Asn1Time::fromString("20000101000000Z");
    auto duration = std::chrono::seconds(std::numeric_limits<int>::max());
    duration *= 366 * 24 * 60 * 60; // Make the number of days exceed MAX_INT

    ASSERT_THROW(asn1time + duration, mococrw::MoCOCrWException);
}

TEST_F(Asn1TimeTest, addingDifferenceMakesEqual)
{
    auto year2000 = Asn1Time::fromString("20000101000000Z");
    auto year2001 = Asn1Time::fromString("20010101000000Z");

    ASSERT_EQ(year2001, year2000 + (year2001 - year2000));
}

TEST_F(Asn1TimeTest, conversionFromAndToStringWorks)
{
    auto year2270 = Asn1Time::fromString("22700101000000Z");

    ASSERT_EQ(year2270, Asn1Time::fromString(year2270.toString()));
}

// In theory we can handle cases where time_t is smaller than Asn1Time.
// In practice, however, this has never been tested, therefore this assert.
TEST_F(Asn1TimeTest, timeTIsLargeEnoughForAsn1Time)
{
    static_assert(sizeof(time_t) >= 5,
                  "time_t is smaller than Asn1Time. This might work, but has never been tested");
}
