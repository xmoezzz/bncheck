#!/usr/bin/env python

import os
import sys
import os.path
import site

try:
    import binaryninja
    print("Binary Ninja API already Installed")
    sys.exit(0)
except ImportError:
    pass

if sys.platform == "linux":
    binaryninja_api_path = "/root/binaryninja/python"
else:
    # Windows
    print("Unsupported os %s" % sys.platform)
    sys.exit(-1)

def validate_path(path):
    try:
        os.stat(path)
    except OSError:
        return False

    old_path = sys.path
    sys.path.append(path)

    try:
        import binaryninja
    except ImportError:
        sys.path = old_path
        return False

    return True

if not validate_path(binaryninja_api_path):
    print("Binary Ninja not found.")
    sys.exit(-1)

import binaryninja
print("Found Binary Ninja core version: {}".format(binaryninja.core_version))

install_path = site.getsitepackages()[0]
binaryninja_pth_path = os.path.join(install_path, 'binaryninja.pth')
open(binaryninja_pth_path, 'w').write(binaryninja_api_path)

print("Binary Ninja API installed")
