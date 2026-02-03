import os
import base64
import textwrap
from kyber_py.kyber import Kyber512

# Dossier où on va tout stocker
KEYS_DIR = "keys"
#os.makedirs(KEYS_DIR, exist_ok=True)

# Liste des stations
STATIONS = ["ST01", "ST02", "ST03", "ST04"]

def to_pem_shared_secret(secret_bytes: bytes) -> str:
    """
    Transforme un secret binaire en texte PEM :
    -----BEGIN STATION SHARED SECRET-----
    BASE64...
    -----END STATION SHARED SECRET-----
    """
    b64 = base64.b64encode(secret_bytes).decode("ascii")
    wrapped = textwrap.fill(b64, 64)
    return (
        "-----BEGIN STATION SHARED SECRET-----\n"
        + wrapped
        + "\n-----END STATION SHARED SECRET-----\n"
    )

def main():
    # 1) Génération de la paire Kyber de l'auditeur
    print("Génération de la paire Kyber de l'auditeur...")
    pk_A, sk_A = Kyber512.keygen()

    # (optionnel) Sauvegarde des clés de l'auditeur
    # Clé publique en base64 (utile si un jour tu veux la partager à part)
    pk_b64 = base64.b64encode(pk_A).decode("ascii")
    with open(os.path.join(KEYS_DIR, "auditor_pk.txt"), "w", encoding="utf-8") as f:
        f.write(pk_b64 + "\n")

    # Clé privée en binaire (à garder très secret côté auditeur)
    with open(os.path.join(KEYS_DIR, "auditor_sk.bin"), "wb") as f:
        f.write(sk_A)

    print("Clés Kyber de l'auditeur générées et stockées dans keys/")

    # 2) Pour l'auditeur : fichier texte avec tous les secrets des stations
    auditor_secrets_path = os.path.join(KEYS_DIR, "auditor_station_secrets.txt")
    auditor_secrets_lines = []

    # 3) Pour chaque station : simuler l'enrôlement et générer le .pem
    for st in STATIONS:
        print(f"[*] Traitement de la station {st}...")

        # Simule côté station : encapsulation avec pk_A
        secret_station, ct_station = Kyber512.encaps(pk_A)

        # Simule côté auditeur : décapsulation de ct_station avec sk_A
        secret_auditor = Kyber512.decaps(sk_A, ct_station)

        # Vérification (optionnelle mais rassurante)
        if secret_station != secret_auditor:
            raise RuntimeError(f"Erreur : secrets différents pour {st} !")

        # On va considérer ce secret comme "secret partagé STxx"
        shared_secret = secret_station

        # 3.a) Fichier .pem pour la station
        pem_text = to_pem_shared_secret(shared_secret)
        station_pem_path = os.path.join(KEYS_DIR, f"{st}_secret.pem")
        with open(station_pem_path, "w", encoding="utf-8") as f:
            f.write(pem_text)

        print(f"    Secret partagé station {st} -> {station_pem_path}")

        # 3.b) Ligne pour le fichier .txt de l'auditeur
        shared_b64 = base64.b64encode(shared_secret).decode("ascii")
        auditor_secrets_lines.append(f"{st}: {shared_b64}")

    # 4) Écrire le fichier de l'auditeur avec tous les secrets
    with open(auditor_secrets_path, "w", encoding="utf-8") as f:
        f.write("\n".join(auditor_secrets_lines) + "\n")

    print(f"Fichier des secrets côté auditeur : {auditor_secrets_path}")
    print("Tous les secrets ont été générés et stockés dans le dossier 'keys'.")

if __name__ == "__main__":
    main()
