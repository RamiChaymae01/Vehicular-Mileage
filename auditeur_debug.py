import os
import json
import time
from dotenv import load_dotenv
from web3 import Web3
import base64

import requests
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Chemin vers l'artifact du contrat
CONTRACT_ARTIFACT_PATH = os.path.join(
    "blockchain", "artifacts", "contracts", "MileageLedger.sol", "MileageLedger.json"
)

# 1) Charger les secrets station↔auditeur
KEYS_DIR = "keys"
def load_auditor_station_secrets():
    """
    Lit keys/auditor_station_secrets.txt et retourne un dict :
    {
      "ST01": secret_bytes,
      "ST02": secret_bytes,
      ...
    }
    """
    secrets_path = os.path.join(KEYS_DIR, "auditor_station_secrets.txt")
    if not os.path.exists(secrets_path):
        raise FileNotFoundError(f"{secrets_path} introuvable")

    secrets = {}
    with open(secrets_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                continue
            station_id, b64 = [p.strip() for p in line.split(":", 1)]
            secret_bytes = base64.b64decode(b64)
            secrets[station_id] = secret_bytes

    return secrets

# 2) Dérivation de la clé AES + déchiffrement IPFS

def derive_aes_key(shared_secret: bytes, station_id: str, salt: bytes) -> bytes:
    """
    Même HKDF que côté station :
    info = "odometer-<station_id>"
    """
    info = f"odometer-{station_id}".encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


def decrypt_ipfs_object(ipfs_obj: dict, shared_secret: bytes):
    """
    - lit station_id, salt, nonce, aad, ciphertext depuis l'objet IPFS
    - dérive la clé AES
    - déchiffre le record JSON
    - renvoie le dict record clair
    """
    station_id = ipfs_obj["station_id"]
    salt = base64.b64decode(ipfs_obj["salt"])
    nonce = base64.b64decode(ipfs_obj["nonce"])
    aad = base64.b64decode(ipfs_obj["aad"])
    ciphertext = base64.b64decode(ipfs_obj["ciphertext"])

    aes_key = derive_aes_key(shared_secret, station_id, salt)
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    record = json.loads(plaintext.decode("utf-8"))
    return record


# 3) Lecture IPFS via Pinata gateway

def fetch_ipfs_json(cid: str) -> dict:
    """
    Récupère le JSON stocké sur IPFS via la gateway Pinata (ou ipfs.io).
    """
    # Gateway Pinata
    url = f"https://gateway.pinata.cloud/ipfs/{cid}"

    resp = requests.get(url)
    if not resp.ok:
        raise RuntimeError(f"Erreur IPFS pour CID {cid}: {resp.status_code} {resp.text}")

    return resp.json()


# 4) Connexion au contrat MileageLedger + filtre d'events
def load_contract(w3: Web3):
    load_dotenv()
    contract_address = os.getenv("MILEAGE_LEDGER_ADDRESS")
    if not contract_address:
        raise RuntimeError("MILEAGE_LEDGER_ADDRESS manquante dans .env")

    if not os.path.exists(CONTRACT_ARTIFACT_PATH):
        raise FileNotFoundError(f"Artifact introuvable: {CONTRACT_ARTIFACT_PATH}")

    with open(CONTRACT_ARTIFACT_PATH, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    abi = artifact.get("abi")
    if not abi:
        raise RuntimeError("ABI introuvable dans l'artifact MileageLedger")

    return w3.eth.contract(
        address=Web3.to_checksum_address(contract_address),
        abi=abi
    )

def main():
    load_dotenv()
    rpc_url = os.getenv("IOTA_RPC_URL")
    if not rpc_url:
        raise RuntimeError("IOTA_RPC_URL manquante dans .env")

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise RuntimeError(f"Impossible de se connecter à l'RPC : {rpc_url}")

    print("[DEBUG-MONITOR] Connecté à IOTA EVM.")
    contract = load_contract(w3)

    # On commence à partir du bloc courant
    last_block = w3.eth.block_number
    print("[DEBUG-MONITOR] Surveillance de MileageDebug à partir du bloc", last_block)
    secrets_by_station = load_auditor_station_secrets()
    print("[AUDITOR] Secrets station↔auditeur chargés pour :", ", ".join(secrets_by_station.keys()))

    try:
        while True:
            latest_block = w3.eth.block_number
            if latest_block > last_block:
                # Récupérer tous les events MileageDebug entre last_block+1 et latest_block
                try:
                    logs = contract.events.MileageDebug().get_logs(
                        fromBlock=last_block + 1,
                        toBlock=latest_block
                    )
                except Exception as e:
                    print(f"[DEBUG-MONITOR] Erreur get_logs: {e}")
                    time.sleep(3)
                    continue

                for ev in logs:
                    args = ev["args"]
                    vehicle_id = args["vehicleId"]
                    prev_km = args["previousOdometerKm"]
                    requested_km = args["requestedOdometerKm"]
                    stored_km = args["newStoredOdometerKm"]
                    prev_fraud = args["previousFraudFlag"]
                    new_fraud = args["newFraudFlag"]

                    print(
                        f"[DEBUG] veh={vehicle_id} "
                        f"prev={prev_km} "
                        f"req={requested_km} "
                        f"stored={stored_km} "
                        f"fraud: {prev_fraud} -> {new_fraud}"
                    )

                # avancer la fenêtre
                last_block = latest_block

            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[DEBUG-MONITOR] Arrêt demandé par l'utilisateur.")


if __name__ == "__main__":
    main()
