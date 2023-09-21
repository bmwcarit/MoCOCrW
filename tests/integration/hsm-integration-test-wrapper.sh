# HSM Integration Test

# Step 1
# Run HSM Integration Test and check results
# This is needed as a first step as we need to store the keys in the HSM
./hsm-integration-test
if [ $? -eq 0 ]; then
  echo "HSM Integration Test was successful"
else
  echo "Error in HSM Integration Test"
  exit 1;
fi

# Step 2
# Run attribute reader to check attributes
./attribute_reader | while read -r line; do
  label="$(cut -d' ' -f1 <<< "${line}")"
  if [ "${label}" == "key-rsa-att" -o "${label}" == "key-ecc-att" ]; then
    if [ "${line}" != "${label} SENSITIVE:0 EXTRACTABLE:1" ]; then
      echo "Manual setting of CKA_SENSITIVE and CKA_EXTRACTABLE failed: ${label}";
      exit 1;
    fi
  else
    if [ "${line}" != "${label} SENSITIVE:1 EXTRACTABLE:0" ]; then
      echo "Automatic setting of CKA_SENSITIVE and CKA_EXTRACTABLE failed: ${label}";
      exit 1;
    fi
  fi

done
echo "Setting CKA_SENSITIVE and CKA_EXTRACTABLE was successful"

