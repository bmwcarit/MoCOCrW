#!/bin/bash

clang-format-10 --version
find . -iname *.h -o -iname *.cpp | xargs clang-format-10 -i
if ! git diff --quiet; then
  git diff
  exit 1
fi

