#!/usr/bin/env python3
"""
cesar.py - Laboratorio 1 (Actividad 2.1)
Cifra un string usando el algoritmo Cesar.

Uso:
    python3 cesar.py "<texto a cifrar>" <corrimiento>

Ejemplo:
    python3 cesar.py "criptografia y seguridad en redes" 9
    -> larycxpajorj h bnpdarmjm nw anmnb
"""

import sys


def cesar_cifrar(texto: str, corrimiento: int) -> str:
    corrimiento = corrimiento % 26
    resultado = []
    for ch in texto:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            nueva = (ord(ch) - base + corrimiento) % 26 + base
            resultado.append(chr(nueva))
        else:
            # espacios, numeros y simbolos se dejan tal cual
            resultado.append(ch)
    return "".join(resultado)


def main():
    if len(sys.argv) != 3:
        print(f"Uso: python3 {sys.argv[0]} \"<texto>\" <corrimiento>")
        sys.exit(1)

    texto = sys.argv[1]
    try:
        corrimiento = int(sys.argv[2])
    except ValueError:
        print("El corrimiento debe ser un numero entero.")
        sys.exit(1)

    cifrado = cesar_cifrar(texto, corrimiento)
    print(cifrado)


if __name__ == "__main__":
    main()
