import binaryninja
import shutil
import sys
import os
from enum import IntEnum
from elftools.elf.elffile import ELFFile

from binaryninja import BinaryViewType

def scan_dir(root: str):
    for (dirpath, dirnames, filenames) in os.walk(root):
        for file in filenames:
            yield os.path.join(dirpath, file)


iv_functions = [
    "wc_AesSetIv",
    "AES_init_ctx_iv",
    "AES_ctx_set_iv",
    "ctr_start",
    "increment_iv"
]


pbe_functions = [
    "EVP_BytesToKey",
]


key_functions = [
    "aes192_set_encrypt_key",
    "aes128_set_encrypt_key",
    "aes256_set_encrypt_key",
    "camellia128_set_encrypt_key",
    "camellia192_set_encrypt_key",
    "camellia256_set_encrypt_key",
    "aes_set_encrypt_key",
    "AES_init_ctx",
    "AES_init_ctx_iv",
    "mbedtls_aes_setkey_enc",
    "mbedtls_aes_setkey_dec",
    "mbedtls_aes_xts_setkey_enc",
    "mbedtls_aes_xts_setkey_dec",
    "mbedtls_arc4_setup",
    "mbedtls_chacha20_setkey",
    "mbedtls_chachapoly_setkey",
    "crypto_poly1305",
    "crypto_chacha20_x_init",
    "crypto_chacha20_init",
    "crypto_chacha20_H",
    "crypto_lock_init",
    "hash_memory",
    "ctr_start",
    "crypto_stream_chacha20",
    "crypto_stream_salsa20",
    "crypto_stream_salsa2012",
    "crypto_stream_xchacha20",
    "crypto_stream_xsalsa20",
    "aes_key_setup",
    "blowfish_key_setup",
    "des_key_setup",
    "three_des_key_setup"
]

ecb_functions = [
    "gcry_cipher_open"
]


salt_functions = [
    "crypt"
]

rand_functions = [
    "srand",
    "init_genrand",
    "init_by_array"
]

class FunctionType(IntEnum):
    RAND = 0,
    IV  = 1,
    KEY = 2,
    SALT = 3,
    ECB = 4,
    PBE = 5


def in_iv_list(buff : bytes):
    for f in iv_functions:
        if buff.find(f.encode(encoding = "utf-8")):
            return True
    return False

def in_key_list(buff : bytes):
    for f in key_functions:
        if buff.find(f.encode(encoding = "utf-8")):
            return True
    return False

def in_rand_list(buff : bytes):
    for f in rand_functions:
        if buff.find(f.encode(encoding = "utf-8")):
            return True
    return False

def in_salt_list(buff : bytes):
    for f in salt_functions:
        if buff.find(f.encode(encoding = "utf-8")):
            return True
    return False

def in_ecb_list(buff : bytes):
    for f in ecb_functions:
        if buff.find(f.encode(encoding = "utf-8")):
            return True
    return False

def in_pbe_list(buff : bytes):
    for f in pbe_functions:
        if buff.find(f.encode(encoding = "utf-8")):
            return True
    return False



def is_elf_file(path: str)->bool:
    try:
        with open(path, "rb") as fd:
            elf = ELFFile(fd)
    except Exception:
        return False
    return True


def main(filename : str):
    for filename in scan_dir('/mnt/disk1/zhao/'):
        if filename.endswith('.ko'):
            continue
        if not is_elf_file(filename):
            continue

        file_type = None
        try:
            with open(filename, 'rb') as fd:
                buff = fd.read()
                if in_iv_list(buff):
                    file_type = "iv"
                elif in_key_list(buff):
                    file_type = "key"
                elif in_salt_list(buff):
                    file_type = "salt"
                elif in_pbe_list(buff):
                    file_type = "pbe"
                elif in_ecb_list(buff):
                    file_type = "ecb"
                elif in_rand_list(buff):
                    file_type = "srand"
                
        except Exception as e:
            print ("Exception : %s" % e)
            continue

        if file_type is None:
            continue

        name = os.path.basename(filename)
        shutil.copy(filename, '/home/xmoe/' + file_type + '/elf/' + name)
        module = BinaryViewType["ELF"].open(filename)
        module.update_analysis_and_wait()
        module.create_database('/home/xmoe/' + file_type + '/bndb/' + name + ".bndb")
        

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit(-1)
    main(sys.argv[1])
