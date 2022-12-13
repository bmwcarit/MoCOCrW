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

#include "mococrw/symmetric_memory.h"

#include <algorithm>
#include <cassert>
#include <queue>

namespace mococrw
{
void QueueOfVectorsMemoryStrategy::write(std::vector<uint8_t> chunk)
{
    _totalBytesStored += chunk.size();
    _queue.emplace_back(std::move(chunk));
}

std::vector<uint8_t> QueueOfVectorsMemoryStrategy::read(size_t requestedBufferSize)
{
    if (_queue.empty()) {
        return std::vector<uint8_t>();
    }

    if (_queue.front().size() == requestedBufferSize) {
        return _readCompleteBlock();
    } else if (_queue.front().size() > requestedBufferSize) {
        std::vector<uint8_t> bufferToReturn;
        bufferToReturn.reserve(requestedBufferSize);
        _readPartialBlock(requestedBufferSize, bufferToReturn);
        return bufferToReturn;
    } else if (_queue.size() == 1) {
        // If the request is larger than the first buffer and we only have one
        // buffer, switch to readAll() to avoid copying the data.
        return readAll();
    } else {
        std::vector<uint8_t> bufferToReturn;
        bufferToReturn.reserve(std::min(requestedBufferSize, _totalBytesStored));
        // First, read as many complete blocks as we can
        while (!_queue.empty() &&
               (_queue.front().size() <= (requestedBufferSize - bufferToReturn.size()))) {
            auto block = _readCompleteBlock();
            std::copy(std::begin(block), std::end(block), std::back_inserter(bufferToReturn));
        }

        // Then, read a partial block if needed
        if (bufferToReturn.size() < requestedBufferSize && !_queue.empty()) {
            _readPartialBlock(requestedBufferSize - bufferToReturn.size(), bufferToReturn);
        }

        return bufferToReturn;
    }
}

std::vector<uint8_t> QueueOfVectorsMemoryStrategy::readAll()
{
    if (_queue.size() == 1) {
        /* If there is only one block, move it rather than copying it. Note
         * that this may be a common case, e.g. when using the following code block:
         *
         *   while (auto input = readInput()) {
         *     cipher->update(input);
         *     writeOutput(cipher->readAll());
         *   }
         */
        auto bufferToReturn = std::move(_queue.front());
        _queue.clear();
        _totalBytesStored = 0;
        return bufferToReturn;
    }

    std::vector<uint8_t> bufferToReturn;
    bufferToReturn.reserve(_totalBytesStored);
    while (!_queue.empty()) {
        std::copy(std::begin(_queue.front()),
                  std::end(_queue.front()),
                  std::back_inserter(bufferToReturn));
        _queue.pop_front();
    }
    _totalBytesStored -= bufferToReturn.size();
    assert((_totalBytesStored == 0) && "Size of the data we hold is not calculated properly.");
    return bufferToReturn;
}

std::vector<uint8_t> QueueOfVectorsMemoryStrategy::_readCompleteBlock()
{
    auto bufferToReturn = std::move(_queue.front());
    _queue.pop_front();
    _totalBytesStored -= bufferToReturn.size();
    return bufferToReturn;
}

void QueueOfVectorsMemoryStrategy::_readPartialBlock(size_t requestedSize,
                                                     std::vector<uint8_t> &output)
{
    assert((_queue.front().size() > requestedSize) && "Callers must not overread the block.");

    auto begin = std::begin(_queue.front());
    auto end = std::begin(_queue.front()) + requestedSize;
    std::copy(begin, end, std::back_inserter(output));
    _queue.front().erase(begin, end);
    _totalBytesStored -= std::distance(begin, end);
}

}  // namespace mococrw
