#!/bin/bash

clang-format --version
find . -iname *.h -o -iname *.cpp | xargs clang-format -i
if ! git diff --quiet; then
  git diff
  exit 1
fi

