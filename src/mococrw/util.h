/**
 * @file
 * @copyright (C) 2017, BMW AG
 * @copyright (C) 2017, BMW Car IT GmbH
 */
#pragma once

#include <memory>

namespace mococrw
{
namespace utility
{

template <class T>
using SharedPtrTypeFromUniquePtr = std::shared_ptr<typename T::element_type>;

}  //::utility
}  //::mococrw
