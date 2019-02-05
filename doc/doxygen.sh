#!/bin/sh
# Wraps a call to doxygen emitting an erroneous exit code if a warning was printed to stderr

set -eu

DOXYGEN_EXECUTABLE="${DOXYGEN_EXECUTABLE:-doxygen}"

if ! $(which "${DOXYGEN_EXECUTABLE}" 2>&1 > /dev/null); then
  echo "Could not find doxygen binary. Please specify its path via DOXYGEN_EXECUTABLE environment variable" >&2
  exit 1
fi

STDERR_LOG=$(mktemp)
trap "rm \"${STDERR_LOG}\" || true" 0

((${DOXYGEN_EXECUTABLE} "${@}") 3>&1 1>&2 2>&3 | tee "${STDERR_LOG}") 3>&1 1>&2 2>&3

if grep -m 1 -q ": warning:" "${STDERR_LOG}"; then
  exit 1
else
  exit 0
fi
