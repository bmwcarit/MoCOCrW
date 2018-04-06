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
#include <fstream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mococrw/bio.h"

using namespace mococrw;
using namespace mococrw::openssl;

const std::string root1CertFilename = "root1.cert1.pem";
const std::string testFileWritePath = "/tmp/testWrite";

TEST(BioTest, testReadingAndWritingToBio)
{
    using ::testing::Eq;
    const std::string someString{"some (not so) random string"};
    BioObject bio{BioObject::Types::MEM};
    bio.write(someString);

    ASSERT_THAT(bio.flushToString(), Eq(someString));

    // check that the BIO is now empty
    ASSERT_THAT(bio.flushToString(), Eq(""));

    bio.write("1234");
    bio.write("abcd");
    ASSERT_THAT(bio.flushToString(), Eq("1234abcd"));
}

TEST(BioTest, testReadingAndWritingToBioInBinary)
{
    using ::testing::Eq;
    const std::vector<uint8_t> someData{0xDE, 0xAD, 0xC0, 0xDE, 0xCA, 0xFE, 0x42};
    BioObject bio{BioObject::Types::MEM};
    bio.write(someData);
    ASSERT_THAT(bio.flushToVector(), Eq(someData));

    // check that the BIO is now empty
    ASSERT_THAT(bio.flushToVector(), Eq(std::vector<uint8_t>{}));

    const std::vector<uint8_t> someDataP1{0xDE, 0xAD, 0xC0, 0xDE};
    const std::vector<uint8_t> someDataP2{0xCA, 0xFE, 0x42};
    bio.write(someDataP1);
    bio.write(someDataP2);
    ASSERT_THAT(bio.flushToVector(), Eq(someData));
}

TEST(BioTest, testOpenFileBioForReading)
{
    ASSERT_NO_THROW({
        // first open it in non binary mode
        FileBio testFileBio(root1CertFilename, FileBio::FileMode::READ, FileBio::FileType::TEXT);
    });
    ASSERT_NO_THROW({
        // now open it in binary mode
        FileBio testFileBio(root1CertFilename, FileBio::FileMode::READ, FileBio::FileType::BINARY);
    });
}

TEST(BioTest, testOpenFileBioForWriting)
{
    ASSERT_NO_THROW({
        // first open it in non binary mode
        FileBio testFileBio(testFileWritePath, FileBio::FileMode::WRITE, FileBio::FileType::TEXT);
    });
    ASSERT_NO_THROW({
        // now open it in binary mode
        FileBio testFileBio(testFileWritePath, FileBio::FileMode::WRITE, FileBio::FileType::BINARY);
    });
}

TEST(BioTest, testOpenNonexistingFileForReading)
{
    ASSERT_THROW({
        FileBio testFileBio("iDoNotExist.file", FileBio::FileMode::READ, FileBio::FileType::TEXT);
    }, OpenSSLException);
}

TEST(BioTest, testOpenAccessDeniedWriting)
{
    ASSERT_THROW({
        FileBio testFileBio("/root/iAmNotAllowedHere.file", FileBio::FileMode::WRITE,
                            FileBio::FileType::TEXT);
    }, OpenSSLException);
}

TEST(BioTest, testFileBioReadingWorks)
{
    using ::testing::Eq;

    // first we load the reference data from the certificate in std c++ way
    std::ifstream file{root1CertFilename};
    ASSERT_TRUE(file.good());

    file.seekg(0, std::ios::end);
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<char> buffer;
    buffer.resize(size);
    file.read(buffer.data(), size);
    std::string referencePemStr(buffer.begin(), buffer.end());

    std::string opensslPemStr;
    ASSERT_NO_THROW({
        FileBio testFileBio(root1CertFilename, FileBio::FileMode::READ, FileBio::FileType::TEXT);
        opensslPemStr = testFileBio.flushToString();
    });
    ASSERT_THAT(referencePemStr, Eq(opensslPemStr));
}
