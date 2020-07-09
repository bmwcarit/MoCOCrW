import unittest
import subprocess
from common import *

AES_ENCRYPT_DATA = "deadbeefbeefdeaddeadbeefbeefdead"
AES_KEY = "000102030405060708090a0b0c0d0e0f"
AES_AUTH_DATA = "beefdead"
AES_IV = "00102030405060708090a0b0c0d0e0f0"
AES_OPTIONAL_ARGS = {
    "padding": ["PKCS", "NO"],
    "iv": [AES_IV]
}

AES_OPERATION_MODES_AND_OPTIONS = {
    "GCM": {
        "optional_args": {
            "auth-data": [AES_AUTH_DATA],
            "auth-tag-length": [16, 8]
        }
    },
    "CTR": {
        "optional_args": {}
    },
    "CBC": {
        "optional_args": {}
    }
}
AES_ENCRYPT_EXEC_STRING = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-aes --encrypt --chaining " \
                                                        "--data {} --key {} --operation-mode {} {}"
AES_DECRYPT_EXEC_STRING = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-aes --decrypt --key {} {}"


class AesTestCase(unittest.TestCase):

    @staticmethod
    def _start_test(args):
        completed_process = subprocess.run(args, capture_output=True)
        return completed_process

    def test_missing_command(self):
        missing_decrypt_encrypt = str(MOCOCRW_EXAMPLE_BINARY_PATH +
                                      "/mococrw-aes "
                                      "--data deadbeef "
                                      "--key 000102030405060708090a0b0c0d0e0f "
                                      "--operation-mode cbc").split(" ")
        result = self._start_test(missing_decrypt_encrypt)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr.strip(), b'You can either decrypt or encrypt the data')

    def test_aes(self):
        for operation_mode, operation_options in AES_OPERATION_MODES_AND_OPTIONS.items():
            options_list = build_option_list({**AES_OPTIONAL_ARGS, **operation_options["optional_args"]})
            for option in options_list:
                encrypt_args = AES_ENCRYPT_EXEC_STRING.format(AES_ENCRYPT_DATA, AES_KEY,
                                                              operation_mode, option)
                result = self._start_test(encrypt_args.split(" "))
                self.assertEqual(result.returncode, 0, "Encryption failed.\nArgs: {}\nError: {}".
                                 format(encrypt_args, result.stderr))

                decrypt_args = AES_DECRYPT_EXEC_STRING.format(AES_KEY,
                                                              result.stdout.decode("ascii").strip())
                result = self._start_test(decrypt_args.split())
                self.assertEqual(result.returncode, 0, "Decrypt failed:\nencrypt: {}\ndecrypt: {}".
                                 format(encrypt_args, decrypt_args))
                self.assertEqual(result.stdout.decode("ascii").strip(), AES_ENCRYPT_DATA)

    def test_invalid_args(self):
        add_invalid_parameters_and_execute([MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-aes"])


if __name__ == '__main__':
    unittest.main()
