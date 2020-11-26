# GoGoGadgetArms!
Aquí encontraréis tres retos: pwnme, ropme y mirror. El grado de dificultad aumenta, en ese orden, aunque los tres son retos "sencillos" que únicamente implican ejecución en stack.
Una vez terminada la charla publicaré los exploits en las respectivas carpetas para que les podáis echar un ojo.

Tanto pwnme como ropme son retos muy simples creados por mí. mirror, sin embargo, es un reto que me encontré durante la HTBxUNI CTF
 y que quería incluir por lo interesante que resulta. Sin embargo, los créditos por este reto corresponden al creador =)
 
### Sobre pwnme y ropme
Los retos pwnme y ropme se encuentran alojados en un VPS para que podáis practicar simulando un entorno de CTF (normalmente, los retos de PWN los vais a encontrar de este modo). Para interactuar con ellos, podéis utilizar netcat:

Reto           | IP              | Port         |        
-------------  | :-------------: |:-------------|
pwnme          | 188.166.120.108 | 10001        |
ropme          | 188.166.120.108 | 10002        |

### IMPORTANTE
Tanto pwnme como ropme están diseñados para ser ejecutados sobre un sistema Linux x64 (se han probado en Debian) con ASLR desactivado. Para ello, ejecutar:
```
echo 0 > /proc/sys/kernel/randomize_va_space
```
