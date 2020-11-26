# GoGoGadgetArms!
Aquí encontraréis tres retos: pwnme, ropme y mirror. El grado de dificultad aumenta, en ese orden, aunque los tres son retos "sencillos" que únicamente implican ejecución en stack.
Una vez terminada la charla publicaré los exploits en las respectivas carpetas para que les podáis echar un ojo.

Tanto pwnme como ropme son retos muy simples creados por mí. mirror, sin embargo, es un reto que me encontré durante la HTBxUNI CTF
 y que quería incluir por lo interesante que resulta. Sin embargo, los créditos por este reto corresponden al creador =)

## IMPORTANTE
Tanto pwnme como ropme están diseñados para ser ejecutados sobre un sistema Linux (se han probado en Debian) con ASLR desactivado. Para ello, ejecutar:
'''
echo 0 > /proc/sys/kernel/randomize_va_space
'''
