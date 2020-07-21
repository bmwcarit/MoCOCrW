import os
import tempfile
import subprocess
import sys

# Get the path to the example binaries from an environment variable
try:
    MOCOCRW_EXAMPLE_BINARY_PATH = os.environ["MOCOCRW_EXAMPLE_BINARY_PATH"]
except KeyError:
    print("Please set the MOCOCRW_EXAMPLE_BINARY_PATH environment variable.", file=sys.stderr)
    sys.exit(1)

# Get the path to the example source dir from an environment variable
try:
    MOCOCRW_SRC_DIR = os.environ["MOCOCRW_SRC_DIR"]
except KeyError:
    print("Please set the MOCOCRW_SRC_DIR environment variable", file=sys.stderr)
    sys.exit(1)


HASH_ALGOS = [
    "SHA256", "SHA384", "SHA512", "SHA3-256", "SHA3-384", "SHA3-512"
]


def add_invalid_parameters_and_execute(parameters):
    parameters.extend(["--awöeljf", "asdölvkjyxc"])
    result = subprocess.run(parameters, capture_output=True)
    assert result.returncode == 1
    assert b"Unknown option selected: unrecognised option '--aw\xc3\xb6eljf'\n" \
           b"Failure parsing command line.\n" == result.stderr


def create_temp_working_dir():
    # Create working directory
    new_working_dir = tempfile.mkdtemp()

    current_working_dir = os.getcwd()
    # Change to working directory
    os.chdir(new_working_dir)
    return current_working_dir, new_working_dir


def combine_all_options(all_options, option_list):
    """
    This function combines the strings in the first string list with the elements of all other
    string lists in all_options and adds the result to all_options.
    e.g.
    all_options = ""
    option_list = [["hello"],["world"]
    result: ["", "hello", "world", "helloworld"]
    :param all_options: List to extend with new entries.
    :param option_list: List of string lists
    :return: A list containing all combination of each single entry of the first list entry with
     all other list entries
    """
    first_options_list = option_list[0]
    add_options = [add_opt + opt for add_opt in first_options_list for opt in all_options]
    all_options += add_options
    if len(option_list) == 1:
        return all_options
    return combine_all_options(all_options, option_list[1:])


def build_option_list(options_dict):
    """
    Builds a list with all possible combinations from the options dict.
    The options in each list are only combined with elements from other lists.
    The options_dict has to consist of a dictionary containing a list as value for each key-value
    pair.
    e.g.
    {
        "blub": ["first", "second"],
        "ship": ["is", "sinking"]
    }
    Nested dicts are not allowed.
    This function would return for the example data given above:
    ["",
     "--blub first", "--blub first --ship is", "--blub first --ship sinking",
     "--blub second", "--blub second --ship is", "--blub second --ship sinking",
     "--ship is",
     "--ship sinking"
    ]
    :param options_dict: A dictionary containing key-value pairs. The value has to be a list of
    strings
    :return: A list which contains all available combinations of the list items. The empty element
    "" is prepended even if options_dict is empty.
    """
    if not options_dict:
        # Returning an empty element
        return [""]
    option_list = []
    for key, values in options_dict.items():
        key_options = []
        for value in values:
            key_options.append("--{} {} ".format(key, value))
        option_list.append(key_options)
    result = combine_all_options([""], option_list)
    return result
