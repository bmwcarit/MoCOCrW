import unittest
import subprocess
from common import *

MAC_EXEC_STRING = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-mac {} {} "


class TestMAC(unittest.TestCase):
    def test_hmac(self):
        key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        message = "4869205468657265"
        expected_tag = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        mac_calculate_string = MAC_EXEC_STRING.format("--calculate",
                                                      "--message {} --key {} --hash-algo sha256".
                                                      format(message, key))

        result = subprocess.run(mac_calculate_string.split(" "), capture_output=True)
        self.assertEqual(result.returncode, 0, "Failure. Exec string: {}. Stderr: {}".
                         format(mac_calculate_string, result.stderr.decode("ascii")))
        self.assertEqual(result.stdout.decode("ascii").strip(), expected_tag)

        mac_calculate_string += " --chaining"
        result = subprocess.run(mac_calculate_string.split(" "), capture_output=True)
        self.assertEqual(result.returncode, 0)

        mac_verify_string = MAC_EXEC_STRING.format("--verify",
                                                   result.stdout.decode("ascii").strip())
        result = subprocess.run(mac_verify_string.split(" "), capture_output=True)
        self.assertEqual(result.returncode, 0, "Failure. Exec string: {}. Stderr: {}".
                         format(mac_verify_string, result.stderr.decode("ascii")))

    def test_invalid_args(self):
        add_invalid_parameters_and_execute([MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-mac"])


if __name__ == '__main__':
    unittest.main()
