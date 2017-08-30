/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#include <iostream>
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
    auto fromGeneralizedTime = Asn1Time::fromString("20170327190038");
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
