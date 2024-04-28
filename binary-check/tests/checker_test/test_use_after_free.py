from ..helpers import load_test_module
import unittest
from analysis.basic import ModuleAnalysisManager, Module
from analysis.checkers.use_after_free import UseAfterFreeChecker

import pytest

@pytest.mark.parametrize("suffix",
                         ["x86_64-O0"])
def test_1(suffix):
    module: Module = load_test_module("./use_after_free/1/main-" + suffix)
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)

    check = mam.get_module_analysis(UseAfterFreeChecker)
    reports = check.get_reports()

    bad_func_names = set()
    for a, b, name in reports:
        assert name.startswith("bug_")
        bad_func_names.add(name)
    assert len(bad_func_names) == 2


# we should always detect those bugs we detected before..
@pytest.mark.parametrize("binary,funcaddr",
        [
            ("use_after_free/real_bug_1/dpkg", 0x1E1E0),
            ("use_after_free/real_bug_2/forked-daapd", 0x411850),
            ("use_after_free/real_bug_3/crashdump_test", 0x11560),
            ("use_after_free/real_bug_4/media-ctl", 0x133BC),
            ("use_after_free/real_bug_5/mkntfs", 0x13E90),
            ("use_after_free/real_bug_6/aoa_server", 0xafe4),
            ("use_after_free/real_bug_7/wifidog", 0x415E78),
            ("use_after_free/real_bug_8/igmp", 0x4056f8),
            ("use_after_free/real_bug_9/dnsmasq", 0x405758),
            ("use_after_free/real_bug_10/sz", 0xE844),
            ("use_after_free/real_bug_11/insserv", 0x9548),
            ("use_after_free/real_bug_12/ripngd", 0x40E0C8),
            ("use_after_free/real_bug_13/libuClibc-0.9.33.3-git.so", 0x12654),
            ("use_after_free/real_bug_14/libebtc.so", 0x43E8),
            ("use_after_free/real_bug_15/libril-rk29-dataonly.so", 0xB7E4),
            ("use_after_free/real_bug_16/igmpproxy", 0x404B64),
            ("use_after_free/real_bug_17/l2tpd", 0x00404AD8),
            ("use_after_free/real_bug_18/libzebra.so.0", 0x2136C),
            ("use_after_free/real_bug_19/openl2tpd", 0x41AE98),
            ("use_after_free/real_bug_20/bftpd", 0x409C44),
            ("use_after_free/real_bug_21/libAuth.so", 0x44D34),
            ("use_after_free/real_bug_22/libupnp.so.2.0.1", 0x77E4),
            ("use_after_free/real_bug_23/sensors", 0x11C04),
            ("use_after_free/real_bug_24/ssh-add", 0x17050),
            ("use_after_free/real_bug_25/cron", 0xAE98),
            ("use_after_free/real_bug_26/busybox", 0x446058),
            ("use_after_free/real_bug_27/ecmh", 0x40A5FC),
        ]
        )
def test_real_bug(binary, funcaddr):

    module: Module = load_test_module(binary)
    mam: ModuleAnalysisManager = ModuleAnalysisManager(module)

    check = mam.get_module_analysis(UseAfterFreeChecker)
    reports = check.get_reports()

    bad_func_names = set()
    for a, b, name in reports:
        print(a, b, name)
        if a.function.source_function.start == funcaddr:
            break
    else:
        assert False, "cannot find the bug function"
        bad_func_names.add(name)
