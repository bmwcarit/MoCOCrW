#! /bin/env python

import sys
import re
import argparse

class Function:

    def __init__(self, returnType, name,  *arguments):
        self._name = name
        self._returnType = returnType.strip()
        self._args = arguments

    def _argumentList(self):
        return ", ".join(x[0] + " " + x[1] for x in self._args)

    def _callStatement(self):
        return self._name + "(" + ", ".join(x[1] for x in self._args) + ")"

    def typeString(self):
        typeString = self._returnType + "("
        typeString += ", ".join([x[0] for x in self._args])
        typeString += ")"
        return typeString

    def _implementation(self, innerLogic):
        implString = self._returnType + " OpenSSLLib::SSL_" + self._name + "("
        implString += self._argumentList() + ") noexcept\n{\n    "
        if self._returnType != "void":
            implString += "return "
        implString += innerLogic + "\n}\n"
        return implString

    def implementationString(self):
        return self._implementation(self._callStatement() + ";")

    def mockImplementationString(self):
        return self._implementation("OpenSSLLibMockManager::getMockInterface().SSL_" + self._callStatement() + ";")

    def declarationString(self):
        s = "    static " + self._returnType + " SSL_" + self._name + "("
        s += self._argumentList()
        s += ") noexcept;\n"
        return s

    def mockupString(self):
        return "    MOCK_METHOD{}({}, {});".format(len(self._args), "SSL_" + self._name, self.typeString()) + "\n"

    def virtualDeclaration(self):
        s = "    virtual " + self._returnType + " SSL_" + self._name + "("
        s += self._argumentList()
        s += ") = 0;\n"
        return s


def injectLines(fileName, matchers, toBeInserted, insertAfter=True):
    with open(fileName, "r") as f:
        lines = f.readlines()
    if not type(matchers) is list:
        matchers = [matchers]
    for i in range(len(lines) - len(matchers) + 1):
        pos = 0
        for matcher in matchers:
            if re.match(matcher, lines[i + pos]):
                pos += 1
            else:
                break
        if pos == len(matchers):
            index = (i + pos) if insertAfter else (i + pos - 1)
            lines = lines[:index] + [toBeInserted] + lines[index:]
            break
    with open(fileName, "w") as f:
        f.writelines(lines)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('returnType', metavar='return type', type=str,
                                help='the return type of the function')
    parser.add_argument("functionName", metavar="function name", type=str, help="the name of the openssl function")
    parser.add_argument("arguments", metavar="arguments", nargs="*", type=str, help="the parameter types and names")
    args = parser.parse_args()

    func = Function(args.returnType, args.functionName, *[(args.arguments[i], args.arguments[i+1]) for i in range(0, len(args.arguments) - 1, 2)])

    injectLines("./src/mococrw/openssl_lib.h", ["class OpenSSLLib", "{", "public:"], func.declarationString())

    injectLines("./src/openssl_lib.cpp", "^\s*}\s*//\s*::lib", func.implementationString(), False)

    injectLines("./tests/unit/openssl_lib_mock.h", ["class OpenSSLLibMockInterface$", "{", "public:"], func.virtualDeclaration())
    injectLines("./tests/unit/openssl_lib_mock.h", ["class OpenSSLLibMock :", "{", "public:"], func.mockupString())

    injectLines("./tests/unit/openssl_lib_mock.cpp", "^\s*}\s*//\s*::lib", func.mockImplementationString(), False)
