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

namespace mococrw
{
namespace utility
{

template<class StackSmartPtrType, class ContainerType>
auto buildStackFromContainer(const ContainerType &cnt) {
    auto stack =
        mococrw::openssl::createManagedOpenSSLObject<StackSmartPtrType>();

    for (const auto &elem : cnt) {
        mococrw::openssl::addObjectToStack(stack.get(), elem.internal());
    }
    return stack;
}

}  //::utility
}  //::mococrw
