/*
 * #%L
 * %%
 * Copyright (C) 2020 BMW Car IT GmbH
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "mococrw/symmetric_memory.h"

using namespace mococrw;

class SymmetricCipherMemoryStrategy : public  ::testing::Test {
protected:
    void SetUp() override {
        for (int i = 0; i < NUMBER_OF_TEST_BLOCKS; i++) {
            std::vector<uint8_t> block(TEST_BLOCK_LENGTH, i);
            _expectedData.insert(std::end(_expectedData), std::begin(block), std::end(block));
        }
    }

    void assembleFromChunksAndCompareWithExpected(
            const std::vector<uint8_t>& expected,
            const std::vector<std::vector<uint8_t>>& actualChunks) const {
        std::vector<uint8_t > readData;
        for (const auto &chunk : actualChunks) {
            readData.insert(std::end(readData), std::begin(chunk), std::end(chunk));
        }
        ASSERT_THAT(readData, ::testing::ElementsAreArray(expected));
    }

    QueueOfVectorsMemoryStrategy sut;

    const int NUMBER_OF_TEST_BLOCKS = 4;
    const int TEST_BLOCK_LENGTH = 16;
    std::vector<uint8_t > _expectedData;
};

TEST_F(SymmetricCipherMemoryStrategy, SeveralWritesAndReadAll) {
    sut.write({std::begin(_expectedData), std::begin(_expectedData) + 3});
    sut.write({std::begin(_expectedData) + 3, std::begin(_expectedData) + 7});
    sut.write({std::begin(_expectedData) + 7, std::end(_expectedData)});

    auto readChunk = sut.readAll();
    ASSERT_THAT(readChunk, ::testing::ElementsAreArray(_expectedData));
}

TEST_F(SymmetricCipherMemoryStrategy, ReadMoreThanQueueHolds) {
    sut.write({std::begin(_expectedData), std::begin(_expectedData) + 3});
    sut.write({std::begin(_expectedData) + 3, std::begin(_expectedData) + 20});

    auto readChunk = sut.read(_expectedData.size());
    ASSERT_EQ(readChunk.size(), 20);
}

TEST_F(SymmetricCipherMemoryStrategy, EmptyReadAll) {
    auto readBlock = sut.read(TEST_BLOCK_LENGTH);
    ASSERT_TRUE(readBlock.empty());
}

TEST_F(SymmetricCipherMemoryStrategy, ReadInWrittenBlockSizes) {
    auto dataPacketizer = std::begin(_expectedData);

    for (int i = 0; i < NUMBER_OF_TEST_BLOCKS - 1; ++i) {
        sut.write({dataPacketizer,
                   dataPacketizer + TEST_BLOCK_LENGTH});
        dataPacketizer += TEST_BLOCK_LENGTH;
    }

    auto readBlock1 = sut.read(TEST_BLOCK_LENGTH);
    auto readBlock2 = sut.read(TEST_BLOCK_LENGTH);

    sut.write({dataPacketizer, dataPacketizer + TEST_BLOCK_LENGTH});
    dataPacketizer += TEST_BLOCK_LENGTH;

    auto readBlock3 = sut.read(TEST_BLOCK_LENGTH);
    auto readBlock4 = sut.read(TEST_BLOCK_LENGTH);

    assembleFromChunksAndCompareWithExpected(_expectedData,
                                             {readBlock1, readBlock2, readBlock3, readBlock4});
}

TEST_F(SymmetricCipherMemoryStrategy, ReadInUnalignedBlockSizes) {
    auto dataPacketizer = std::begin(_expectedData);
    for (int i = 0; i < NUMBER_OF_TEST_BLOCKS - 1; ++i) {
        sut.write({dataPacketizer, dataPacketizer + TEST_BLOCK_LENGTH});
        dataPacketizer += TEST_BLOCK_LENGTH;
    }

    auto readBlock1 = sut.read(TEST_BLOCK_LENGTH / 2);
    auto readBlock2 = sut.read(TEST_BLOCK_LENGTH * 1.6);

    sut.write({dataPacketizer, dataPacketizer + TEST_BLOCK_LENGTH});
    dataPacketizer += TEST_BLOCK_LENGTH;

    auto readBlock3 = sut.read(TEST_BLOCK_LENGTH);
    auto readBlock4 = sut.readAll();

    assembleFromChunksAndCompareWithExpected(_expectedData,
                                             {readBlock1, readBlock2, readBlock3, readBlock4});
}
