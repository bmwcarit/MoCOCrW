import os
import unittest
import shutil
import subprocess
from common import *


RSA_SIGN_EXEC_STRING = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-rsa --encrypt --data {} " \
                                                     "--public-key {} --chaining {}"
RSA_VERIFY_EXEC_STRING = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-rsa --decrypt --private-key {} {}"
# If the first digit is too large, openssl complains about it:
# error:04068084:rsa routines:rsa_ossl_public_encrypt:data too large for modulus: 67534980'
DATA = "0eadbeefbeefdead"
INVALID_DATA = "no-hex-string"

class RsaTest(unittest.TestCase):
    def setUp(self) -> None:
        self.old_working_dir, self.working_dir = create_temp_working_dir()

    def tearDown(self) -> None:
        os.chdir(self.old_working_dir)
        # delete working directory
        shutil.rmtree(self.working_dir)

    @staticmethod
    def _generate_oaep_options():
        labels = ["", "--oaep-label This is my test label"] * 3
        my_list = ["oaep --oaep-hash-algo {} {}".format(algo, label)
                   for algo, label in zip(HASH_ALGOS, labels)]
        return my_list

    def _create_key(self):
        self.priv_key = "key.pem"
        self.pub_key = "keyPub.pem"
        key_exec_string = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-key {} {}"
        args = key_exec_string.format("--rsa", "--pub-out --pub-out-file {} --out-file {}".
                                      format(self.pub_key, self.priv_key))
        result = subprocess.run(args.split(), capture_output=True)
        self.assertEqual(result.returncode, 0, "Failed to generate encrypted key")

    def test_rsa_sign_and_verify(self):
        self._create_key()
        optional_args = {"padding": [*self._generate_oaep_options(), "no", "pkcs"]}
        option_list = build_option_list(optional_args)
        for option in option_list:
            data = DATA
            if "no" in option:
                # For no-padding the data size has match the following condition:
                # len(data) * 8 == key_size_in_bits
                # as the data is in hex we only divide by 4 (instead of 8)
                data = "".join([DATA] * int(2048 / 4 / len(DATA)))
            encrypt_string = RSA_SIGN_EXEC_STRING.format("".join(data), self.pub_key, option)
            encrypt_result = subprocess.run(encrypt_string.split(), capture_output=True)
            self.assertEqual(encrypt_result.returncode, 0, "Failure encrypting data. "
                                                           "Command: {}. Error: {}/{}".
                             format(encrypt_string, encrypt_result.stdout, encrypt_result.stderr))

            decrypt_string = RSA_VERIFY_EXEC_STRING.format(self.priv_key,
                                                          encrypt_result.stdout.decode("ascii"))
            decrypt_result = subprocess.run(decrypt_string.split(), capture_output=True)
            self.assertEqual(decrypt_result.returncode, 0, "Failure decrypting data. Command: {}\n"
                                                           "Encrypt command: {}\nError: {}/{}".
                             format(decrypt_string, encrypt_string,
                                    decrypt_result.stdout, decrypt_result.stderr))

            self.assertEqual(decrypt_result.stdout.decode("ascii").strip(), "".join(data))

    def test_invalid_args(self):
        add_invalid_parameters_and_execute([MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-rsa"])

    def test_invalid_data(self):
        self._create_key()
        encrypt_string = RSA_SIGN_EXEC_STRING.format(INVALID_DATA, self.pub_key, "")
        encrypt_result = subprocess.run(encrypt_string.split(), capture_output=True)
        self.assertEqual(encrypt_result.returncode, 1)
        self.assertEqual(b'Failure in crypto engine: Invalid hex string: no-hex-string\n',
                         encrypt_result.stderr)


if __name__ == '__main__':
    unittest.main()
