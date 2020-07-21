import unittest
import subprocess
import os
import shutil
import json
from common import *

DSA_SIGN_EXEC_STRING = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-sig --sign --message {} " \
                                                     "--private-key {} {}"
DSA_VERIFY_EXEC_STRING = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-sig --verify --public-key {} {}"

VARIANTS_AND_OPTIONAL_ARGS = {
    "ecc": {
        "key_type": "ecc",
        "basename": "ecc{}.pem",
        "optional_args": {
            "signature-format": ["ASN1", "IEEE1363"],
            "hash-algo": HASH_ALGOS
        }
    },
    "ed": {
        "key_type": "ecc",
        "basename": "ed{}.pem",
        "optional_args": {
            "hash-algo": HASH_ALGOS
    }
    },
    "rsa": {
        "key_type": "rsa",
        "basename": "rsa{}.pem",
        "optional_args": {
            "padding": ["PKCS", "PSS", "PSS --pss-salt-len 512"],
            "hash-algo": HASH_ALGOS
        }
    }
}
MESSAGE = "0x48656c6c6f206d7920737765657420776f726c6421"
INVALID_MESSAGE = "i-am-no-hex-string"

CERT_CREATE_CONFIG = {
    "signer-cert": {
        "certDetails": {
            "commonName": "Self Signed Signature Cert",
            "countryName": "DE",
            "localityName": "hometown",
            "stateOrProvinceName": "BW",
            "organizationName": "I am cup",
            "organizationalUnitName": "Test",
            "pkcs9EmailAddress": "myEMail@mail.de",
            "givenName": "I sign everything"
        },
        "keyUsage": {
            "decipherOnly": False,
            "encipherOnly": False,
            "cRLSign": False,
            "keyCertSign": False,
            "keyAgreement": False,
            "dataEncipherment": False,
            "nonRepudiation": False,
            "digitalSignature": True
        },
        "basicConstraints": {
            # MoCOCrW can't sign non CA self signed certificates
            "isCA": True
        },
        "certificateValiditySeconds": 31536000,
        "digestType": "SHA512"
    }
}


class DsaTestCase(unittest.TestCase):

    @classmethod
    def _create_keys(cls, key_private_name, key_public_name, key_type, optional_params):
        key_create_string = MOCOCRW_EXAMPLE_BINARY_PATH + \
                            "/mococrw-key --{} --out-file {} --pub-out --pub-out-file {} {}".format(
                                key_type, key_private_name, key_public_name, optional_params)
        result = subprocess.run(key_create_string.split(" "), capture_output=True)
        if result.returncode != 0:
            print("Failed to execute {}: {}".format(key_create_string, result.stderr))
            assert False, "I mean for this to fail"

    @classmethod
    def setUpClass(cls) -> None:
        cls.old_working_dir, cls.working_dir = create_temp_working_dir()
        # Create keys
        for key_section, value in VARIANTS_AND_OPTIONAL_ARGS.items():
            if key_section == "ecc":
                # create ecc keyType and cert
                cls._create_keys(value["basename"].format("Priv"), value["basename"].format("Pub"),
                                 value["key_type"], "--curve SECT_571r1")
            elif key_section == "ed":
                # create ed keyType
                cls._create_keys(value["basename"].format("Priv"), value["basename"].format("Pub"),
                                 value["key_type"], "--curve Ed25519")
            elif key_section == "rsa":
                # create rsa keyType and cert
                cls._create_keys(value["basename"].format("Priv"), value["basename"].format("Pub"),
                                 value["key_type"], "--key-size 4096")
            else:
                assert False, "Unknown keyType {}".format(value["key_type"])

    @classmethod
    def tearDownClass(cls) -> None:
        os.chdir(cls.old_working_dir)
        # delete working directory
        shutil.rmtree(cls.working_dir)

    def test_dsa(self):
        for operation_mode, operation_options in VARIANTS_AND_OPTIONAL_ARGS.items():
            optional_args_list = build_option_list(operation_options["optional_args"])
            for optional_args in optional_args_list:
                sign_string = DSA_SIGN_EXEC_STRING.format(
                    MESSAGE,
                    operation_options["basename"].format("Priv"),
                    optional_args
                )
                sign_string += " --chaining "
                result = subprocess.run(sign_string.split(" ", ), capture_output=True)
                self.assertEqual(result.returncode, 0)
                sign_result = result.stdout.decode("ascii")

                verify_string = DSA_VERIFY_EXEC_STRING.format(
                    operation_options["basename"].format("Pub"),
                    sign_result.strip()
                )
                result = subprocess.run(verify_string.split(" "),
                                        capture_output=True)
                self.assertEqual(result.returncode, 0, "Sign: {}\nSign result: {}\nVerify: {}".
                                 format(sign_string, sign_result,
                                        verify_string))

    def test_invalid_args(self):
        add_invalid_parameters_and_execute([MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-sig"])

    def test_invalid_message(self):
        sign_string = DSA_SIGN_EXEC_STRING.format(
                    INVALID_MESSAGE,
                    "ecc{}.pem".format("Priv"),
                    ""
                )
        encrypt_result = subprocess.run(sign_string.split(), capture_output=True)
        self.assertEqual(encrypt_result.returncode, 1)
        self.assertEqual(b'Failure reading message.\nInvalid hex string: i-am-no-hex-string\n',
                         encrypt_result.stderr)

    def test_cert(self):
        with open("cert-config.json", "w") as config_file:
            json.dump(CERT_CREATE_CONFIG, config_file, indent=4)

        cert_name = "signer-cert.pem"
        priv_key = "eccPriv.pem"
        pub_key = "eccPub.pem"
        create_cert_string = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-ca --create " \
                                                           "--config-file cert-config.json " \
                                                           "--config-section signer-cert " \
                                                           "--private-key {} " \
                                                           "--output-path {}".format(priv_key,
                                                                                     cert_name)
        result = subprocess.run(create_cert_string.split(" "), capture_output=True)
        self.assertEqual(result.returncode, 0, "Failure creating signer cert.")

        sign_string = DSA_SIGN_EXEC_STRING.format(
                    MESSAGE,
                    priv_key,
                    "--chaining"
                )
        result = subprocess.run(sign_string.split(" ", ), capture_output=True)
        self.assertEqual(result.returncode, 0)
        sign_result = result.stdout.decode("ascii")

        verify_string = MOCOCRW_EXAMPLE_BINARY_PATH + "/mococrw-sig --verify --cert {} {}".\
            format(
                cert_name,
                sign_result.strip()
            )
        result = subprocess.run(verify_string.split(" "),
                                capture_output=True)
        self.assertEqual(result.returncode, 0, "Sign: {}\nSign result: {}\nVerify: {}".
                         format(sign_string, sign_result,
                                verify_string))


if __name__ == '__main__':
    unittest.main()
