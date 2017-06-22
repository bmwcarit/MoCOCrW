/*   Copyright 2016,2017 Marcus Gelderie
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */

#pragma once

#include <cerrno>
#include <cstring>
#include <functional>
#include <sstream>
#include <stdexcept>
#include <type_traits>
#include <utility>

#include "boost/format.hpp"

namespace cppc {

namespace _auxiliary {

template <class T>
using EnableIfIsPrecallFunc = std::enable_if_t<std::is_same<T, void()>::value>;

template <class T, class = EnableIfIsPrecallFunc<decltype(T::preCall)>>
inline void _callIf(void*) {
    T::preCall();
}

template <class... Ts>
inline void _callIf(Ts*...) {}

template <class T>
inline void callPrecCallIfPresent() {
    _callIf<T>(nullptr);
}

/**
 * Let's define C++17's  void_t helper-template.
 */
template <class...>
struct _VoidT {
    using type = void;
};
template <class... Ts>
using VoidT = typename _VoidT<Ts...>::type;

/**
 * Helper template to wrap the handling of error conditions and return codes.
 * This is necessary to obtain a correct return value (in case of
 * return-value-modifying ErrorPolicies) without complication to
 * function-template 'callChecked' (defined below).
 */
template <class ReturnCheckPolicy, class ErrorPolicy, class Rv, class = VoidT<>>
struct ReturnCheckWrapper {
    template <class R>
    inline static Rv policyHandeledReturnValue(const R& rv) {
        if (!ReturnCheckPolicy::returnValueIsOk(rv)) {
            ErrorPolicy::handleError(rv);
        }
        return rv;
    }
};

/**
 * Template specialization that handles the case where an ErrorPolicy modifies
 * the returnValue. This is recognized by inspecting the 'handleOk' function, its
 * type and the return value of both 'handleOk' and 'handleError' (they must
 * match).
 */
template <class ReturnCheckPolicy, class ErrorPolicy, class Rv>
struct ReturnCheckWrapper<ReturnCheckPolicy,
                          ErrorPolicy,
                          Rv,
                          VoidT<decltype(ErrorPolicy::handleOk(std::declval<Rv>()))>> {
    template <class R>
    inline static auto policyHandeledReturnValue(const R& rv) {
        if (!ReturnCheckPolicy::returnValueIsOk(rv)) {
            return ErrorPolicy::handleError(rv);
        }
        return ErrorPolicy::handleOk(rv);
    }
};

}  // ::_auxiliary

struct ReportReturnValueErrorPolicy {
    template <class Rv>
    static void handleError(const Rv& rv);
};

template <class Rv>
void ReportReturnValueErrorPolicy::handleError(const Rv& rv) {
    boost::format fmtr{"Return value indicated error: %d"};
    fmtr % rv;
    throw std::runtime_error(fmtr.str());
}

struct ErrnoErrorPolicy {
    template <class Rv>
    static void handleError(const Rv&);
};

template <class Rv>
void ErrnoErrorPolicy::handleError(const Rv&) {
    throw std::runtime_error(std::strerror(errno));
}

struct ErrorCodeErrorPolicy {
    template <class Rv>
    static void handleError(const Rv& rv);
};

template <class Rv>
void ErrorCodeErrorPolicy::handleError(const Rv& rv) {
    static_assert(std::is_integral<std::decay_t<Rv>>::value, "Must be an integral value");
    throw std::runtime_error(std::strerror(-rv));
}

using DefaultErrorPolicy = ReportReturnValueErrorPolicy;

struct IsZeroReturnCheckPolicy {
    template <class Rv>
    static inline bool returnValueIsOk(const Rv& rv) {
        static_assert(std::is_integral<std::decay_t<Rv>>::value, "Must be an integral value");
        return rv == 0;
    }
};

struct IsNotNegativeReturnCheckPolicy {
    template <class Rv>
    static inline bool returnValueIsOk(const Rv& rv) {
        static_assert(std::is_integral<std::decay_t<Rv>>::value, "Must be an integral value");
        static_assert(std::is_signed<std::decay_t<Rv>>::value, "Must be a signed type");

        return rv >= 0;
    }
};

struct IsNotZeroReturnCheckPolicy {
    template <class Rv>
    static inline bool returnValueIsOk(const Rv& rv) {
        static_assert(std::is_integral<std::decay_t<Rv>>::value, "Must be an integral value");
        static_assert(std::is_signed<std::decay_t<Rv>>::value, "Must be a signed type");

        return rv != 0;
    }
};

struct IsNotNullptrReturnCheckPolicy {
    template <class Rv>
    static inline bool returnValueIsOk(const Rv& rv) {
        return nullptr != rv;
    }
};

struct IsErrnoZeroReturnCheckPolicy {
    template <class Rv>
    static inline bool returnValueIsOk(const Rv&) {
        return errno == 0;
    }
    static inline void preCall() { errno = 0; }
};

using DefaultReturnCheckPolicy = IsZeroReturnCheckPolicy;

template <class R = DefaultReturnCheckPolicy,
          class E = DefaultErrorPolicy,
          class Callable = std::function<void(void)>,
          class... Args>
inline auto callChecked(Callable&& callable, Args&&... args) {
    ::cppc::_auxiliary::callPrecCallIfPresent<R>();
    const auto retVal = callable(std::forward<Args>(args)...);
    return _auxiliary::ReturnCheckWrapper<R, E, decltype(retVal)>::policyHandeledReturnValue(
            retVal);
}

template <class Functor,
          class ReturnCheckPolicy = DefaultReturnCheckPolicy,
          class ErrorPolicy = DefaultErrorPolicy>
class CallGuard {
private:
    using FunctorOrFuncRefType = std::conditional_t<std::is_function<Functor>::value,
                                                    std::add_lvalue_reference_t<Functor>,
                                                    Functor>;

public:
    template <class T>
    CallGuard(T&& t) : _functor{std::forward<T>(t)} {}

    template <class T = Functor,
              typename = std::enable_if_t<std::is_default_constructible<T>::value>>
    CallGuard() : _functor{} {}

    template <class... Args>
    auto operator()(Args&&... args) {
        return callChecked<ReturnCheckPolicy, ErrorPolicy>(_functor, std::forward<Args>(args)...);
    }

private:
    FunctorOrFuncRefType _functor;
};

template <class ReturnCheckPolicy = DefaultReturnCheckPolicy,
          class ErrorPolicy = DefaultErrorPolicy>
class CallCheckContext {
public:
    template <class Callable, class... Args>
    static inline auto callChecked(Callable&& callable, Args&&... args) {
        return ::cppc::callChecked<ReturnCheckPolicy, ErrorPolicy>(
                std::forward<Callable>(callable), std::forward<Args>(args)...);
    }
};

}  // namespace cppc
