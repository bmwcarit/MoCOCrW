import os
import unittest
import shutil
import subprocess
from common import *

ECIES_ENCRYPT_COMMAND = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-ecies --encrypt --chaining " \
                                                      "--public-key {} --data {} {}"
ECIES_DECRYPT_COMMAND = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-ecies --decrypt --private-key {} {}"
DATA = "0xdeadbeefed"


class EciesTestCase(unittest.TestCase):

    def setUp(self) -> None:
        self.old_working_dir, self.working_dir = create_temp_working_dir()

    def tearDown(self) -> None:
        os.chdir(self.old_working_dir)
        # delete working directory
        shutil.rmtree(self.working_dir)

    def _create_keypair(self):
        self.priv_key = "key.pem"
        self.pub_key = "keyPub.pem"
        key_exec_string = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-key --{} {}"
        args = key_exec_string.format("ecc", "--pub-out --pub-out-file {} --out-file {}".
                                      format(self.pub_key, self.priv_key))
        result = subprocess.run(args.split(), capture_output=True)
        self.assertEqual(result.returncode, 0, "Failed to generate encrypted key")

    @staticmethod
    def _get_optional_args_dict():
        hash_len = ["256", "384", "512"] * 2
        mac_algos = ["{} --mac-algo HMAC --mac-key-size {} ".format(algo, algo_len)
                     for algo, algo_len in zip(HASH_ALGOS, hash_len)]

        def build_kdf_combinations():
            kdf_combis = []
            for kdf in ["X963KDF", "PBKDF2"]:
                for iterations in ["1024", "512"]:
                    for hash_algo in HASH_ALGOS:
                        kdf_combis.append("{} --kdf-hash-algo {} --kdf-algo-iterations {}".format(
                            kdf, hash_algo, iterations))
            return kdf_combis

        return {
            "mac-hash-algo": [*mac_algos],
            "kdf-algo": build_kdf_combinations(),
            "eph-key-form": ["uncompressed", "hybrid", "compressed"]
        }

    def test_ecies(self):
        self._create_keypair()
        option_list = build_option_list(self._get_optional_args_dict())
        for option in option_list:
            encrypt_string = ECIES_ENCRYPT_COMMAND.format(
                self.pub_key,
                DATA,
                option
            )
            result = subprocess.run(encrypt_string.split(" ", ), capture_output=True)
            self.assertEqual(result.returncode, 0, "Encrypt: {}, error: {}".format(encrypt_string,
                             result.stderr))
            encrypt_result = result.stdout.decode("ascii")

            decrypt_string = ECIES_DECRYPT_COMMAND.format(
                self.priv_key,
                encrypt_result.strip()
            )
            result = subprocess.run(decrypt_string.split(" "),
                                    capture_output=True)
            self.assertEqual(result.returncode, 0, "Encrypt: {}\n"
                                                   "Encrypt result: {}\n"
                                                   "Decrypt: {}\n"
                                                   "Error: {}".
                             format(encrypt_string, encrypt_result,
                                    decrypt_string, result.stderr))
            self.assertEqual(DATA.replace("0x", ""), result.stdout.decode("ascii").strip())
        pass

    def test_invalid_args(self):
        add_invalid_parameters_and_execute([MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-ecies"])

if __name__ == '__main__':
    unittest.main()
