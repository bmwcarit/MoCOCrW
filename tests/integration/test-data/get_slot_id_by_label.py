#!/usr/bin/python3

import argparse
import json
import re
import sys


def parse_args():
    parser = argparse.ArgumentParser(
        prog="get_slot_id_by_label",
        description="Returns the slot id for a given label",
    )
    parser.add_argument(
        "--label", type=str, help="The name/label of the slot", required=True
    )
    parser.add_argument(
        "pkcs_data", nargs="?", help="If not set the content of stdin is read"
    )

    args = parser.parse_args()
    return args

# Slot 0 (0x180cd37e): SoftHSM slot ID 0x180cd37e
ID_RE = re.compile(r"Slot [\d]+ \((?P<id>0[xX][0-9a-fA-F]+)\):.*")


def main():
    args = parse_args()
    pkcs_data = ""
    if not args.pkcs_data:
        for line in sys.stdin:
            pkcs_data += line
    else:
        pkcs_data = args.pkcs_data

    pkcs_data = json.loads(pkcs_data)

    for _object in pkcs_data:
        header = list(_object.keys())[0]
        values = _object[header]
        try:
            if values["token label"] == args.label:
                match = ID_RE.match(header)
                if not match:
                    raise RuntimeError(f"Couldn't extract ID from header: {header}")
                print(match["id"])
                exit(0)
        except KeyError:
            continue

    print(f"slot with label \"{args.label}\" couldn't be found.")
    exit(1)


if __name__ == "__main__":
    main()
