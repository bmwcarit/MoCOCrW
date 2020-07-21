import unittest
import subprocess
from common import *

KDF_EXEC_STRING = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-kdf --hash-algo {} --password {} " \
                                                "--output-length {} {} "


class MyTestCase(unittest.TestCase):
    def test_pbkdf2(self):
        hash_algo = "SHA512"
        password = "password".encode("ascii").hex()
        salt = "salt".encode("ascii").hex()
        iterations = 1
        output_length = 64
        expected_result = "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d47" \
                          "0a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"

        exec_string = KDF_EXEC_STRING.format(hash_algo, password, output_length,
                                             "--iterations {} --pbkdf2 --salt {}".
                                             format(iterations, salt))
        result = subprocess.run(exec_string.split(), capture_output=True)

        self.assertEqual(result.returncode, 0, "PBKDF2 failed. Exec string: {}. Stderr: {}".
                         format(exec_string, result.stderr.decode("ascii")))
        self.assertEqual(result.stdout.decode("ascii").strip(), expected_result)

    def test_x963kdf(self):

        hash_algo = "SHA256"
        password = "96c05619d56c328ab95fe84b18264b08725b85e33fd34f08"
        salt = "\"\""
        output_length = int(128 / 8)
        expected_result = "443024c3dae66b95e6f5670601558f71"

        exec_string = KDF_EXEC_STRING.format(hash_algo, password, output_length, "--x963kdf")
        result = subprocess.run(exec_string.split(), capture_output=True)

        self.assertEqual(result.returncode, 0, "Stdout: {}. Stderr {}. Command: {}".
                         format(result.stdout, result.stderr, exec_string))
        self.assertEqual(result.stdout.decode("ascii").strip(), expected_result)

    def test_invalid_args(self):
        add_invalid_parameters_and_execute([MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-mac"])


if __name__ == '__main__':
    unittest.main()
