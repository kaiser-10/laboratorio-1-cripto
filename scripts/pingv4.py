#!/usr/bin/env python3
"""
pingv4.py - envia un string caracter por caracter en paquetes ICMP
echo request hacia una IP de loopback, uno por segundo.

Uso: sudo python3 pingv4.py "<texto cifrado>" <ip_destino>
"""

import random
import sys
import time

from scapy.all import IP, ICMP, Raw, send, wrpcap

PATRON = bytes(range(0x10, 0x38))  # 40 bytes: 0x10 .. 0x37, igual que ping por defecto


def construir_payload(caracter: str) -> bytes:
    """Arma un payload ICMP de 48 bytes: 3 bytes coherentes (con el dato
    encubierto adentro) + 5 bytes en 0x00 + el patron 0x10..0x37."""
    ahora = int(time.time())
    coherente = bytes([ord(caracter) & 0xFF, (ahora >> 8) & 0xFF, ahora & 0xFF])
    ceros = bytes(5)
    return coherente + ceros + PATRON  # 3 + 5 + 40 = 48 bytes


def enviar_stealth(texto: str, destino: str, delay: float = 1.0):
    icmp_id = random.randint(1, 0xFFFF)       # se mantiene fijo toda la sesion
    ip_id_base = random.randint(1, 0xFFFF)    # base para que el IP id sea incremental

    print(f"[+] Sesion stealth: ICMP id=0x{icmp_id:04x}")

    paquetes = []
    for seq, caracter in enumerate(texto, start=1):
        payload = construir_payload(caracter)
        pkt = (IP(dst=destino, id=(ip_id_base + seq) & 0xFFFF)
               / ICMP(type=8, code=0, id=icmp_id, seq=seq)
               / Raw(load=payload))
        send(pkt, verbose=0)
        paquetes.append(pkt)
        print("Sent 1 packets.")
        time.sleep(delay)
    return paquetes


def main():
    if len(sys.argv) != 3:
        print(f"Uso: sudo python3 {sys.argv[0]} \"<texto cifrado>\" <ip_destino>")
        sys.exit(1)

    texto = sys.argv[1]
    destino = sys.argv[2]

    paquetes = enviar_stealth(texto, destino)

    wrpcap("stealth_capture.pcap", paquetes)
    print(f"\nTrafico guardado en stealth_capture.pcap ({len(paquetes)} paquetes).")


if __name__ == "__main__":
    main()
