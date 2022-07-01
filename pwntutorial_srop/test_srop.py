from pwn import *

message = "Hello, World\\n"
context.clear(arch='i386')
assembly =  'setup: sub esp, 1024\n'
assembly += 'read:'      + shellcraft.read(constants.STDIN_FILENO, 'esp', 1024)
assembly += 'sigreturn:' + shellcraft.sigreturn()
assembly += 'int3:'      + shellcraft.trap()
assembly += 'syscall: '  + shellcraft.syscall()
assembly += 'exit: '     + 'xor ebx, ebx; mov eax, 1; int 0x80;'
assembly += 'message: '  + ('.asciz "%s"' % message)
binary = ELF.from_assembly(assembly)
frame = SigreturnFrame(kernel='amd64')
frame.eax = constants.SYS_write
frame.ebx = constants.STDOUT_FILENO
frame.ecx = binary.symbols['message']
frame.edx = len(message)
frame.esp = 0xdeadbeef
frame.eip = binary.symbols['syscall']
p = process(binary.path)
p.send(bytes(frame))
print(p.recvline())

p.poll(block=True)
