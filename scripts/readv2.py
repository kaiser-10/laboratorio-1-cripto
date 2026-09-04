#!/usr/bin/env python3
"""
readv2.py - reconstruye el mensaje enviado por pingv4.py a partir de
un pcap y prueba las 26 combinaciones de descifrado Cesar, destacando
en verde la mas probable.

Uso: sudo python3 readv2.py <archivo.pcapng>
"""

import sys

from scapy.all import rdpcap, ICMP, Raw

VERDE = "\033[92m"
RESET = "\033[0m"

PATRON = bytes(range(0x10, 0x38))  # firma que arma pingv4.py (40 bytes)

# Frecuencia relativa (%) de letras en espanol, para elegir el
# corrimiento mas probable por chi-cuadrado.
FREQ_ESPANOL = {
    'a': 12.53, 'b': 1.42, 'c': 4.68, 'd': 5.86, 'e': 13.68, 'f': 0.69,
    'g': 1.01, 'h': 0.70, 'i': 6.25, 'j': 0.44, 'k': 0.02, 'l': 4.97,
    'm': 3.15, 'n': 6.71, 'o': 8.68, 'p': 2.51, 'q': 0.88, 'r': 6.87,
    's': 7.98, 't': 4.63, 'u': 3.93, 'v': 0.90, 'w': 0.02, 'x': 0.22,
    'y': 0.90, 'z': 0.52,
}


def es_paquete_stealth(pkt) -> bool:
    if not (pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and pkt.haslayer(Raw)):
        return False
    data = bytes(pkt[Raw].load)
    return (len(data) == 48
            and data[3:8] == bytes(5)      # 5 bytes en 0x00 (un timestamp real casi nunca los tiene)
            and data[8:48] == PATRON)      # patron fijo 0x10..0x37


def extraer_mensaje(pcap_path: str) -> str:
    """Reconstruye el string enviado a partir de los ICMP echo request
    del canal encubierto, ordenados por numero de secuencia. El dato
    encubierto va en el primer byte del payload (ver pingv4.py).

    En la interfaz loopback (lo) cada paquete se captura DOS veces
    (una de salida y otra de entrada), por lo que se descartan seq
    repetidos y solo se toma un caracter por numero de secuencia."""
    paquetes = rdpcap(pcap_path)
    por_seq = {}
    for pkt in paquetes:
        if es_paquete_stealth(pkt):
            data = bytes(pkt[Raw].load)
            por_seq.setdefault(pkt[ICMP].seq, data[0])  # se queda con la 1ra ocurrencia

    mensaje = "".join(chr(por_seq[seq]) for seq in sorted(por_seq))
    return mensaje


def cesar_descifrar(texto: str, corrimiento: int) -> str:
    resultado = []
    for ch in texto:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            nueva = (ord(ch) - base - corrimiento) % 26 + base
            resultado.append(chr(nueva))
        else:
            resultado.append(ch)
    return "".join(resultado)


def puntaje_chi_cuadrado(texto: str) -> float:
    """Mientras mas bajo el puntaje, mas se parece la distribucion de
    letras del texto a la del espanol -> mas probable que sea el
    mensaje en claro."""
    letras = [c for c in texto.lower() if c.isalpha()]
    n = len(letras)
    if n == 0:
        return float("inf")

    conteo = {letra: 0 for letra in FREQ_ESPANOL}
    for c in letras:
        if c in conteo:
            conteo[c] += 1

    chi2 = 0.0
    for letra, freq_esperada in FREQ_ESPANOL.items():
        esperado = freq_esperada / 100 * n
        observado = conteo[letra]
        if esperado > 0:
            chi2 += (observado - esperado) ** 2 / esperado
    return chi2


def main():
    if len(sys.argv) != 2:
        print(f"Uso: sudo python3 {sys.argv[0]} <archivo.pcapng>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    mensaje_cifrado = extraer_mensaje(pcap_path)

    candidatos = []
    for corrimiento in range(26):
        texto = cesar_descifrar(mensaje_cifrado, corrimiento)
        score = puntaje_chi_cuadrado(texto)
        candidatos.append((corrimiento, texto, score))

    mejor_corrimiento = min(candidatos, key=lambda c: c[2])[0]

    print("corrimiento\ttexto")
    for corrimiento, texto, score in candidatos:
        if corrimiento == mejor_corrimiento:
            print(f"{VERDE}{corrimiento}\t\t{texto}   <- llave mas probable{RESET}")
        else:
            print(f"{corrimiento}\t\t{texto}")


if __name__ == "__main__":
    main()
