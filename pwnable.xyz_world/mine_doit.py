from pwn import *

# Pwnable.xyz Message challenge

context(kernel="amd64", arch="amd64", log_level="debug")

# win offset: 0x00AD6
#do_seed use srand

def main():
	e = ELF("challenge")
	env = dict(os.environ)
	# env["LD_PRELOAD"] = "./ld.so.2 ./libc.so.6"
	if 1:
		p = process(e.path, env=env)
		# gdb.attach(p)
	elif 0:
		p = process(["strace", "-o", "strace.out", e.path])
	else:
		p = remote("svc.pwnable.xyz", 30015)


main()