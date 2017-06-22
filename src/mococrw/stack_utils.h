/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
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
