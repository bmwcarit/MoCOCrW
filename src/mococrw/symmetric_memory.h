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

#pragma once

#include <memory>
#include <queue>
#include <vector>

namespace mococrw
{
class CipherMemoryStrategyI
{
public:
    virtual ~CipherMemoryStrategyI() = default;

    virtual void write(std::vector<uint8_t> block) = 0;
    virtual std::vector<uint8_t> read(size_t blockSize) = 0;
    virtual std::vector<uint8_t> readAll() = 0;
};

class QueueOfVectorsMemoryStrategy : public CipherMemoryStrategyI
{
public:
    void write(std::vector<uint8_t> chunk) override;
    std::vector<uint8_t> read(size_t chunkSize) override;
    std::vector<uint8_t> readAll() override;

private:
    std::vector<uint8_t> _readCompleteBlock();
    void _readPartialBlock(size_t requestedSize, std::vector<uint8_t>& output);
    std::deque<std::vector<uint8_t>> _queue;
    size_t _totalBytesStored = 0;
};

}  // namespace mococrw
