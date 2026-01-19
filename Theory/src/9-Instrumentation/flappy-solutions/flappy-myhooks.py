#!/usr/bin/env python3
import frida
import sys

# Nome del processo come appare su "ps" o "htop" (modifica se serve)
process_name = "flappy"  # O "./flappy" oppure il nome corretto del binario in esecuzione

session = frida.attach(process_name)
with open("flappy-gameover.js") as f:
    script = session.create_script(f.read())

def on_message(message, data):
    print(message)

script.on('message', on_message)
script.load()
print('[*] Hook attivo. Premi invio per uscire.')
sys.stdin.read()
session.detach()
