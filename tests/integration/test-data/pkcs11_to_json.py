#!/usr/bin/python3

"""
This tool parses the output of "pkcs11-tool" and returns it as json document.
"""

import argparse
import json
import re
import sys


"""
Output of pkcs11-tool looks like the following
<Object1-name> 
  <key1>:     <value1>
  <key2>:     <value2>
  ...
<Object2-name>
...
"""
OBJECT_START_RE = re.compile(r"[^\t ].*$")
PARSE_RE = re.compile(r"[ \t]+(?P<key>[\w\-,\. ]*):[ \t]+(?P<value>[\w\-,\. ]*)")


def isObjectStart(line: str):
    if OBJECT_START_RE.match(line):
        return True
    return False


def getObject(line: str):
    if isObjectStart(line):
        return False
    return True


def parsePrivateObject(object: list):
    parsed_object = {}
    header = object[0]
    for line in object[1:]:
        match = PARSE_RE.match(line)
        if match:
            parsed_object[match["key"].strip()] = match["value"]
    return {header: parsed_object}


def parse_objects(data: str):
    object_found = False
    objects_strings = []
    cur_object = []
    for line in data.split("\n"):
        if not line:
            continue
        if object_found:
            if getObject(line):
                cur_object.append(line)
            else:
                # End of current object start of new object
                objects_strings.append(cur_object)
                cur_object = []
                object_found = False
        if not object_found and isObjectStart(line):
            # new object found
            object_found = True
            cur_object.append(line)
    if cur_object:
        objects_strings.append(cur_object)

    # Create a list and not a dict because object-names can be the same
    ret_val = []
    for _object in objects_strings:
        parsed_object = parsePrivateObject(_object)
        if not parsed_object:
            continue
        ret_val.append(parsed_object)
    return ret_val


def parse_args():
    parser = argparse.ArgumentParser(
        prog="pkcs11_to_json",
        description="Reads pkcs11-tool output from stdin and returns it as json file on stdout",
    )
    return parser.parse_args()


def main():
    parse_args()
    data = ""
    for line in sys.stdin:
        data += line
    objects = parse_objects(data)
    print(json.dumps(objects, indent=4))


if __name__ == "__main__":
    main()
