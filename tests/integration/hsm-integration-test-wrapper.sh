#!/bin/sh

# HSM Integration Test

set -ex

TEST_DATA_DIR="@CMAKE_CURRENT_SOURCE_DIR@"

# Run HSM Integration Test and check results
# This is needed as a first step as we need to store the keys in the HSM
./hsm-integration-test

# get slot id
SLOT_ID=$(pkcs11-tool -L --module /usr/lib/softhsm/libsofthsm2.so \
    | ${TEST_DATA_DIR}/test-data/pkcs11_to_json.py \
    | ${TEST_DATA_DIR}/test-data/get_slot_id_by_label.py --label token-label2)

echo "slot id $SLOT_ID"

# Check key attribues
pkcs11-tool --slot "${SLOT_ID}" --pin 1234 --so-pin 4321 -O --module /usr/lib/softhsm/libsofthsm2.so \
    | ${TEST_DATA_DIR}/test-data/pkcs11_to_json.py \
    | ${TEST_DATA_DIR}/test-data/private_key_attribute_validator.py \
        --check_config ${TEST_DATA_DIR}/test-data/check_config.json
