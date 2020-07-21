import unittest
import subprocess
from common import *

HASH_EXEC_STRING = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-hash --hash-algo {} --message {} "
HASH_MESSAGE = "deadbeeffeedbac1"

# created using "echo -n deadbeeffeedbac1 | openssl dgst -DIGEST -hex"
EXPECTED_RESULTS = {
    "SHA256":   "3ed569f33e288852f400e48e6ac2c06c6d4b48203bd2e83b2cd40c755e9733f3",
    "SHA384":   "552069a189967c1e917bec65b0b5136341d4f2b199a8f927106ec02cb606619213fe5610f9e88d6af4575fa3fa5114a5",
    "SHA512":   "6f70516f9136da4df50f23d43b10a3ed02aceded48c4c2937f5fd1391358efd4702a1af39e85fcaec77c59418e4131eb460e200a7edb450f4d05ea0af33c0649",
    "SHA3-256": "265fef8743d60605eb66cfb11b9a46c97cafdbe8d9ac6c2fb4af08f8977a7284",
    "SHA3-384": "aa3b664435f29a656fbc9161add5c97a81f10a4650573e628e43ac281033e28baca4bb936be45cc62487e2a0826b2ccb",
    "SHA3-512": "611bf20a5bb712c9c7accecf5541eabfd234afa75ac1f57ccc7d548ed0ccff15bbaf69aa3998b93b2c9f1dbd853fc221727762135f6ece09ae46893d31668e70"
}


class MyTestCase(unittest.TestCase):
    def test_hash(self):
        for algo, result in EXPECTED_RESULTS.items():
            execute_string = HASH_EXEC_STRING.format(algo, HASH_MESSAGE)
            proc = subprocess.run(execute_string.split(), capture_output=True)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(result, proc.stdout.decode("ascii").strip())

    def test_invalid_args(self):
        add_invalid_parameters_and_execute([MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-hash"])


if __name__ == '__main__':
    unittest.main()
