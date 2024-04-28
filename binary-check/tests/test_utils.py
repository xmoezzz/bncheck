from .helpers import load_test_module
import analysis.utils as utils


def test_get_ascii_string_at():
    bv = load_test_module("./simple_example_1/main")

    assert utils.get_ascii_string_at(bv, 0x40061b) == "a: %s %s\n"


def test_get_bytes_at():
    bv = load_test_module("./simple_example_1/main")

    assert utils.get_bytes_at(bv, 0x40061b, 9) == b"a: %s %s\n"
