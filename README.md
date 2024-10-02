# WebMod Stack Buffer Overflow CVE-2007-1260
by cybermind (Kevin Masterson)  
cybermind@gmail.com

WebMod site (archived): https://web.archive.org/web/20080517044559/http://djeyl.net/w.php

Vulnerable versions:  
0.48, both Win32 and Linux. Previous versions may be vulnerable. This should work with any version of HLDS.

Vulnerability type:  
DoS, Remote code execution under the user HLDS is running under.

Description:
When receiving an HTTP POST request, it allocates 11 bytes on the stack to store the value for Content-Length, but writes into that buffer until a newline or null terminator is received. After your Content-Length string reaches 158308 bytes, it begins overwriting the EIP. This number may be slightly different on Linux due to padding. Your shellcode must not contain 0x00, 0x0A, or 0x0D or else it will stop reading data from the socket.

This may assist in executing your shellcode:
* For Win32:  
  There is an "FF E4" (jmp esp) in w_mm.dll v0.48 at 0x67E03C5B
* For Linux:  
  There is an "FF E4" (jmp esp) in metamod_i386.so v1.19 at offset 0x0008835C


Proof-of-concept code:  
w48crash.c  
Note: The "shellcode" used in the PoC is hardcoded specifically to work with a server running on Win2K SP4/kernel32.dll/user32.dll v5.0.2195.6688. The actual buffer overflow will work as-is on any Windows version, however. To test this, you can set the "our_eip" global variable to 0xFFFFFFFF to simply cause a crash.

Cause/Fix:  
The problem code is from lines 542-552 in server.cpp:

    542        char clbuf[11];
    543
    544        for(i=0;(size_t)i<strlen(input)-17;i++)
    545        {
    546            if(!strnicmp(input+i,"\nContent-Length: ",17))
    547            {
    548 LOG_DBG_SERVER(("Content-length spotted"));
    549                i+=17;
    550                for(j=0;input[i]!='\n'&&input;[i];i++,j++)
    551                    clbuf[j]=input[i];
    552                clbuf[j]='\0';

The buffer, clbuf, allocated on line 542, is written into with the loop on lines 550-551, and then null-terminated. The fix is to replace line 550 with:

    550                for(j=0;input[i]!='\n'&&input[i]&&j<10;i++,j++)
