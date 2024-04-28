from __future__ import print_function
import os
import sys
import subprocess
import shutil

_parent_dir = os.path.dirname(os.path.abspath(__file__))
sys.path = [os.path.join(_parent_dir, 'packages')] + sys.path

import elftools

def check(filename):
    output = './result/' + os.path.basename(filename)

    with open(filename, 'rb') as fd:
        buf = fd.read(4)
        if buf != '\x7F\x45\x4C\x46':
            return True
        
    try:
        print("processing -> %s" % filename)
        p = subprocess.Popen(['python', 'BinaryChecker.py', '-i', filename, '-d', 'ida:cwe:backdoor:port:hardcode', '-o', output])
        code = p.wait()
        print('code = %x' % code)
        if code != 0:
            return False
    except:
        return False
    return True


def scan(root):
    for (dirpath, dirnames, filenames) in os.walk(root):
        for filename in filenames:
            yield os.path.join(dirpath, filename)

def copy_crash_sample(filename):
    try:
        dest = os.path.join('./crashes', os.path.basename(filename))
        shutil.copyfile(filename, dest)
    except:
        pass


if __name__ == "__main__":
    cnt = 0
    if len(sys.argv) < 2:
        sys.exit(-1)
    root = sys.argv[1]
    for filename in scan(root):
        try:
            status = check(filename)
            print('%d checked' % cnt)
            if status == False:
                copy_crash_sample(filename)
        except:
            pass
        cnt = cnt + 1
        with open('/tmp/BinaryScanner.unix', 'w') as fd:
            fd.write("process : %d\n" % cnt)