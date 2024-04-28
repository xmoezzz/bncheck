import binaryninja
import shutil
import sys
import os
import subprocess

def scan_dir(root: str):
    for (dirpath, dirnames, filenames) in os.walk(root):
        for file in filenames:
            yield os.path.join(dirpath, file)


def main():
    for filename in scan_dir('/mnt/disk1/zhao/'):
        if filename.endswith('.ko'):
            continue

        p = subprocess.Popen(["python3", "./sub.py", filename])
        p.wait()
        print(filename)
        

if __name__ == '__main__':
    main()

