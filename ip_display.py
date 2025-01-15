#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import time
import sys

try:
    import netifaces
except ImportError:
    print("La bibliothèque 'netifaces' n'est pas installée. Exécutez :")
    print("  pip install netifaces")
    sys.exit(1)

try:
    from tabulate import tabulate
except ImportError:
    print("La bibliothèque 'tabulate' n'est pas installée. Exécutez :")
    print("  pip install tabulate")
    sys.exit(1)

def clear_screen():
    """
    Efface l'écran du terminal pour un nouvel affichage.
    Compatible Windows / Mac / Linux (si le terminal supporte les séquences ANSI).
    """
    print("\033[2J\033[H", end='')  # ANSI escape: clear screen + move cursor to home

def get_ip_table(verbose=False):
    """
    Récupère les interfaces réseau et retourne une liste de lignes 
    [Interface, IP, Masque, Broadcast (optionnel)].
    """
    table_data = []
    for interface in netifaces.interfaces():
        ifaddresses = netifaces.ifaddresses(interface)

        if netifaces.AF_INET in ifaddresses:
            inet_info = ifaddresses[netifaces.AF_INET]
            for addr in inet_info:
                ip       = addr.get('addr')
                netmask  = addr.get('netmask', '')
                broadcast= addr.get('broadcast', '')

                # Ne pas ajouter si ip est None ou vide
                if ip:
                    if verbose:
                        table_data.append(
                            [interface, ip, netmask, broadcast]
                        )
                    else:
                        # Si on n'est pas en mode verbeux, on affiche juste l'interface et l'IP
                        table_data.append(
                            [interface, ip]
                        )
    return table_data

def afficher_ips(verbose=False):
    """
    Construit et affiche le tableau des IP sur la sortie standard.
    """
    table_data = get_ip_table(verbose)

    if not table_data:
        print("Aucune interface active avec une adresse IPv4 trouvée.")
        return

    if verbose:
        # Entêtes de colonnes plus complètes
        headers = ["Interface", "IP", "Masque", "Broadcast"]
    else:
        # Version simple
        headers = ["Interface", "IP"]

    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))

def main():
    parser = argparse.ArgumentParser(
        description="Affiche l’adresse IP des interfaces réseau (tableau) sur Windows, macOS ou Linux."
    )
    parser.add_argument(
        "-l", "--loop",
        help="Boucle d'affichage. Rafraîchit l'écran à chaque intervalle (défaut 2s).",
        action="store_true"
    )
    parser.add_argument(
        "-i", "--interval",
        help="Intervalle en secondes pour le rafraîchissement (utilisé si --loop). Par défaut : 2",
        type=float,
        default=2.0
    )
    parser.add_argument(
        "-v", "--verbose",
        help="Affiche des informations supplémentaires (masque, broadcast).",
        action="store_true"
    )

    args = parser.parse_args()

    if not args.loop:
        # Un seul affichage et on quitte
        afficher_ips(verbose=args.verbose)
    else:
        try:
            while True:
                clear_screen()
                afficher_ips(verbose=args.verbose)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nArrêt du script.")

if __name__ == "__main__":
    main()

