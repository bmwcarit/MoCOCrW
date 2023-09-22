#!/usr/bin/python3
import argparse
import json
import pathlib
import sys


def remove_public_key_entries(pkcs11_data: list):
    ret_val = []
    for entry in pkcs11_data:
        keys = entry.keys()
        if "Private" in list(keys)[0]:
            ret_val.append(entry)
    return ret_val


def change_key_to_id(entry):
    header = list(entry.keys())[0]
    return {entry[header]["ID"]: entry[header]}


def change_to_dict_with_id_as_key(data: list):
    ret_val = {}
    for entry in data:
        ret_val.update(change_key_to_id(entry))
    return ret_val


def parse_args():
    parser = argparse.ArgumentParser(
        prog="private_key_attribute_validator",
        description="Compares private keys as reported by pkcs11-tool with a json file. "
                    "If private key entries are identical the check passes.",
    )
    parser.add_argument(
        "--check_config",
        type=pathlib.Path,
        required=True,
        help="A json file containing the checks",
    )
    parser.add_argument(
        "pkcs11_json", nargs="?", help="If not set the content of stdin is read"
    )

    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    pkcs11_json = ""
    if not args.pkcs11_json:
        for line in sys.stdin:
            pkcs11_json += line
    else:
        pkcs11_json = args.pkcs11_json
    pkcs11_data = json.loads(pkcs11_json)
    pkcs11_data = remove_public_key_entries(pkcs11_data)
    pkcs11_dict = change_to_dict_with_id_as_key(pkcs11_data)

    check_config = json.loads(args.check_config.read_text())
    check_dict = change_to_dict_with_id_as_key(check_config)
    success = check_dict == pkcs11_dict

    if success:
        print("Successfully checked the key attributes.")
        exit(0)
    else:
        print("Checking the key attributes failed.")
        print(f"Check config:\n{json.dumps(check_config, indent=4)}")
        print(
            f"pkcs11 json without public keys dict/stdin:\n{json.dumps(pkcs11_data, indent=4)}"
        )
        exit(1)


if __name__ == "__main__":
    main()
