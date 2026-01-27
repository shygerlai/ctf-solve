#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'

p=remote('134.209.237.231', 4248)
for i in range(201):
	p.recvuntil('is :')
	p.send(p.recvline())

p.interactive()
p.close()
