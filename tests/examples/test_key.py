import os
import unittest
import subprocess
import shutil
from common import *

KEY_EXEC_STRING = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-key --{} {}"
KEY_OPTIONS = {
    "rsa": [
        "",
        "--key-size 512",
        "--key-size 4096"
    ]
    ,
    "ecc": [
        "",
        "--curve SECT_571r1",
        "--curve PRIME_192v1",
        "--curve PRIME_256v1",
        "--curve SECP_224r1",
        "--curve SECP_384r1",
        "--curve SECP_521r1",
        "--curve SECT_283k1",
        "--curve SECT_283r1",
        "--curve SECT_409k1",
        "--curve SECT_409r1",
        "--curve SECT_571k1",
        "--curve SECT_571r1",
        "--curve Ed448",
        "--curve Ed25519"
    ]
}


class KeyTestCase(unittest.TestCase):

    def setUp(self) -> None:
        self.old_working_dir, self.working_dir = create_temp_working_dir()

    def tearDown(self) -> None:
        os.chdir(self.old_working_dir)
        # delete working directory
        shutil.rmtree(self.working_dir)

    def test_key_generation(self):
        for mode, options in KEY_OPTIONS.items():
            for option in options:
                key_args = KEY_EXEC_STRING.format(mode, option).split(" ")
                result = subprocess.run(key_args, capture_output=True)
                self.assertEqual(result.returncode, 0, "Key generation failed.")

                openssl_check_string = "openssl pkey -check"
                from subprocess import Popen, PIPE, STDOUT
                p = Popen(openssl_check_string.split(), stdout=PIPE, stdin=PIPE, stderr=PIPE)
                # Write the key to stdin of openssl
                p.communicate(input=result.stdout)[0]
                p.wait()
                stdout, stderr = p.communicate()
                self.assertEqual(p.returncode, 0, "Failure checking key: {}/{}\nError message: "
                                                  "{}/{}"
                                 .format(mode, option, stdout, stderr))

    def test_key_encryption(self):
        filename = "encryptedKey.pem"
        password = "123456"
        args = KEY_EXEC_STRING.format("ecc", "--password {} --out-file {}".
                                      format(password, filename))
        result = subprocess.run(args.split(), capture_output=True)
        self.assertEqual(result.returncode, 0, "Failed to generate encrypted key")

        openssl_args = "openssl ec -noout -in {} -passin pass:{}".format(filename, password)
        result = subprocess.run(openssl_args.split(), capture_output=True)
        self.assertEqual(result.returncode, 0)

    def test_pub_out(self):
        filename = "key.pem"
        args = KEY_EXEC_STRING.format("ecc", "--pub-out --out-file {}".
                                      format(filename))
        result = subprocess.run(args.split(), capture_output=True)
        self.assertEqual(result.returncode, 0, "Failed to generate encrypted key")
        pub_out = result.stdout.decode("ascii").strip()

        openssl_args = "openssl ec -pubout -in {}".format(filename)
        result = subprocess.run(openssl_args.split(), capture_output=True)
        self.assertEqual(result.returncode, 0)

        self.assertEqual(pub_out, result.stdout.decode("ascii").strip(), "Exec string: {}".
                         format(args))

    def test_invalid_args(self):
        add_invalid_parameters_and_execute([MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-key"])

if __name__ == '__main__':
    unittest.main()
