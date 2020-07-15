import unittest
import tempfile
import os
import subprocess
import shutil
from common import *

CONFIG_FILE = MOCOCRW_SRC_DIR + "/example-ca.json"


class CaAndCsrTests(unittest.TestCase):

    @classmethod
    def _create_key(cls, keyname):
        create_string = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-key --ecc --curve SECT_571r1"
        result = subprocess.run(create_string.split(), capture_output=True)
        if result.returncode != 0:
            print("Failed to execute " + create_string)
            assert False, "I mean for this to fail"
        with open(os.path.join(cls.working_dir, keyname), "wb") as f:
            f.write(result.stdout)

    def _create_csr(self, csr_name, config_file, config_section, private_key):
        create_csr_string = MOCOCRW_EXAMPLE_BINARY_PATH + \
                        "/mococrw-csr " \
                        "--config-file {} " \
                        "--config-section {} " \
                        "--private-key {}".format(config_file, config_section, private_key)
        result = subprocess.run(create_csr_string.split(), capture_output=True)
        self.assertEqual(result.returncode, 0, "Failed to create certificate signing request."
                                               "Exec string: {}. Stderr: {}".
                         format(create_csr_string, result.stderr.decode("ascii")))
        with open(os.path.join(self.working_dir, csr_name), "wb") as f:
            f.write(result.stdout)

    def _sign_csr(self, ca_key_name, ca_cert_name, config_file, config_section, csr, cert_name):
        sign_csr_string = MOCOCRW_EXAMPLE_BINARY_PATH + \
                        "/mococrw-ca " \
                        "--sign " \
                        "--config-file {} " \
                        "--config-section {} " \
                        "--private-key {} " \
                        "--ca-cert {} " \
                        "--csr {}".format(config_file, config_section, ca_key_name, ca_cert_name,
                                          csr)
        result = subprocess.run(sign_csr_string.split(), capture_output=True)
        self.assertEqual(result.returncode, 0, "Failed to sign certificate: {}".
                         format(result.stderr.decode("ascii")))
        with open(os.path.join(self.working_dir, cert_name), "wb") as f:
            f.write(result.stdout)

    @classmethod
    def setUpClass(cls) -> None:
        cls.oldCwd, cls.working_dir = create_temp_working_dir()

        # Create keys (ca, intermediate ca, leaf)
        cls.root_ca_key_name = "rootCaKey.pem"
        cls.root_ca_cert_name = "rootCa.pem"
        cls._create_key(cls.root_ca_key_name)

        cls.intermediate_ca_key_name = "intermediateCaKey.pem"
        cls.intermediate_ca_csr_name = "intermediateCaCsr.pem"
        cls.intermediate_ca_cert_name = "intermediateCa.pem"
        cls._create_key(cls.intermediate_ca_key_name)

        cls.leaf_cert_key_name = "leafCertKey.pem"
        cls.leaf_csr_name = "leafCsr.pem"
        cls.leaf_cert_name = "leafCert.pem"
        cls._create_key(cls.leaf_cert_key_name)

    @classmethod
    def tearDownClass(cls) -> None:
        os.chdir(cls.oldCwd)
        # delete working directory
        shutil.rmtree(cls.working_dir)

    def test_1_create_root_ca(self):
        create_string = MOCOCRW_EXAMPLE_BINARY_PATH + \
                        "/mococrw-ca " \
                        "--create " \
                        "--config-file {} " \
                        "--config-section root-cert " \
                        "--private-key {}".format(CONFIG_FILE, self.root_ca_key_name)
        result = subprocess.run(create_string.split(), capture_output=True)
        self.assertEqual(result.returncode, 0, "Failed to create self-signed root certificate."
                                               "Exec string: {}. Stderr: {}".
                         format(create_string, result.stderr.decode("ascii")))
        with open(os.path.join(self.working_dir, self.root_ca_cert_name), "wb") as f:
            f.write(result.stdout)

        # Test for validity with openssl
        test_string = "openssl x509 -noout -in {}".format(self.root_ca_cert_name)
        result = subprocess.run(test_string.split(), capture_output=True)
        self.assertEqual(result.returncode, 0)

    def test_2_create_intermediate_Ca(self):
        self._create_csr(csr_name=self.intermediate_ca_csr_name, config_file=CONFIG_FILE,
                         config_section="ca-cert", private_key=self.intermediate_ca_key_name)

        self._sign_csr(ca_key_name=self.root_ca_key_name, ca_cert_name=self.root_ca_cert_name,
                       config_file=CONFIG_FILE, config_section="rootca-sign",
                       csr=self.intermediate_ca_csr_name, cert_name=self.intermediate_ca_cert_name)

        # Verify the certificate
        verify_string = "openssl verify -CAfile {} {}".format(self.root_ca_cert_name,
                                                            self.intermediate_ca_cert_name)
        result = subprocess.run(verify_string.split(), capture_output=True)
        self.assertEqual(result.returncode, 0, "Failed to verify intermediate CA.")

    def test_3_create_leaf_cert(self):
        self._create_csr(csr_name=self.leaf_csr_name,
                         config_file=CONFIG_FILE,
                         config_section="leaf-cert-1",
                         private_key=self.leaf_cert_key_name)
        self._sign_csr(ca_key_name=self.intermediate_ca_key_name,
                       ca_cert_name=self.intermediate_ca_cert_name,
                       config_file=CONFIG_FILE, config_section="ca-sign",
                       csr=self.leaf_csr_name,
                       cert_name=self.leaf_cert_name)

        pemChain = b""
        with open(self.root_ca_cert_name, "rb") as f:
            pemChain += f.read()
        with open(self.intermediate_ca_cert_name, "rb") as f:
            pemChain += f.read()

        # Verify the certificate
        verify_string = "openssl verify -CAfile {} -untrusted {} {}".format(
            self.root_ca_cert_name,
            self.intermediate_ca_cert_name,
            self.leaf_cert_name)
        result = subprocess.run(verify_string.split(), capture_output=True)
        self.assertEqual(result.returncode, 0, "Failed to verify leaf certificate.")

    def test_invalid_args(self):
        add_invalid_parameters_and_execute([MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-ca"])
        add_invalid_parameters_and_execute([MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-csr"])


if __name__ == '__main__':
    unittest.main()
