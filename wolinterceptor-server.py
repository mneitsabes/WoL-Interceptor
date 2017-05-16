#! /usr/bin/python3

import socket
import hashlib
import hmac
import datetime
import io
import binascii
import os
import pwd
import grp

# Configuration
HMAC_KEY = "SHARED_SECRET"
RELAYSERVER_IP = "RELAY IP HERE"
RELAYSERVER_PORT = 8000
WOL_PORT = 9
LOG_FILE = "/var/log/wol.log"
LOG_TIMESTAMP_FORMAT = "%d/%m/%Y %H:%M:%S"
PROCESS_USER_NAME = "user"
PROCESS_UID = 1000 # ID of the user
PROCESS_GROUP_NAME = "user"
PROCESS_GID = 1000 # GID of the group
# Fin de la configuration

# Génération de la clé pour le HMAC
HMAC_KEY = bytearray(HMAC_KEY, "utf-8")

'''
Permet de dropper les privilèges du process de root vers un autre utilisateur/groupe

Source : http://stackoverflow.com/questions/2699907/dropping-root-permissions-in-python
'''
def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    if os.getuid() != 0:
        # We're not root so, like, whatever dude
        return

    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)

    # Ensure a very conservative umask
    old_umask = os.umask(77)

'''
Récupère la date et l'heure courante sous la forme d'une chaîne au format DD-MM-YYYY HH:MM:SS

:return la date
'''
def getCurrentTimeStr():
    return datetime.datetime.now().strftime(LOG_TIMESTAMP_FORMAT)

'''
Ecrit, dans le fichier log, un message de log en le préfixant de la date et heure courante

:param msg le message
'''
def log(msg):
    FP_LOG.write("[{}] {}\n".format(getCurrentTimeStr(), msg))
    FP_LOG.flush()

# Ouvre le log
FP_LOG = io.open(LOG_FILE, "a", encoding="utf-8")

# On créé le socket qui va écoute l'UDP
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# On veut recevoir le broadcast
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

# On bind aucune IP (par défault le broadcast donc) et le port utilisé pour le WoL
sock.bind(('', WOL_PORT))

log("Server initialized...")

# On devait être "root" pour binder les ports, maintenant nous allons donc downgrader les privilèges vers l'utilisateur et groupe "user"
drop_privileges(PROCESS_USER_NAME, PROCESS_GROUP_NAME)

if os.getuid() != PROCESS_UID or os.getgid() != PROCESS_GID:
    log("Cannot drop root privileges, exiting now !")
    exit(-1)
else:
    log("Root privileges dropped, ready to intercept and relaying !")

# On traite tout ce qui passe
while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes

    # Un paquet commence par "0xFFFFFFFFFFFF" suivi de 16x l'adresse MAC (et à donc une longueur fixe de 102 bytes)
    if len(data) == 102:
        mac = data[6:12]

        wolPacket = b'\xff\xff\xff\xff\xff\xff'
        for i in range(16):
            wolPacket += mac

        # C'est un paquet WoL valide
        if data == wolPacket:
            # On créé le socket du client et on se connecte au relay
            client = socket.socket()
            client.connect((RELAYSERVER_IP, RELAYSERVER_PORT))

            # On format l'adresse MAC sous la forme d'une chaine au format "XX:XX:XX:XX:XX:XX"
            macStr = binascii.hexlify(mac).decode("utf8")
            macIterator = iter(macStr)
            macStr = ":".join(a + b for a, b in zip(macIterator, macIterator))

            # On l'envoit au relais
            client.send(macStr.encode("utf8"))

            # On récupère le challenge du serveur
            challenge = client.recv(1024)

            # Que l'on signe avec la clé secrète partagée
            sign = hmac.new(HMAC_KEY, challenge, hashlib.sha256)

            # On la renvoit et on peut se déconnecter
            client.send(sign.hexdigest().encode("utf8"))
            client.close()

            log("Relaying waking up request for %s" % macStr)
        else:
            log("Packet is invalid")
