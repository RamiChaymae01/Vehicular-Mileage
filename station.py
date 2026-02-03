import os
import sys
import json
import base64
from datetime import datetime

import requests
from dotenv import load_dotenv

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from web3 import Web3

# -----------------------------
# CONFIG GLOBALE
# -----------------------------

KEYS_DIR = "keys"

# Chemin vers l'artifact Hardhat du contrat MileageLedger
CONTRACT_ARTIFACT_PATH = os.path.join(
    "blockchain", "artifacts", "contracts", "MileageLedger.sol", "MileageLedger.json"
)

# Données DÉTERMINISTES par station
STATION_RECORDS = {
    "ST01": [
        {
            "vehicle_id": "CAR1",
            "odometer_km": 700000,
            "source": "STATION_AUTOROUTE",
        },
        {
            "vehicle_id": "CAR1",
            "odometer_km": 120500,
            "source": "STATION_AUTOROUTE",
        },
        {
            "vehicle_id": "CAR1",
            "odometer_km": 90300,
            "source": "STATION_AUTOROUTE",
        },
        {
            "vehicle_id": "CAR1",
            "odometer_km": 45000,
            "source": "STATION_AUTOROUTE",
        },
        {
            "vehicle_id": "CAR1",
            "odometer_km": 130500,
            "source": "STATION_AUTOROUTE",
        }

    ]
}

# -----------------------------
# UTILITAIRES : chargement secret + dérivation AES
# -----------------------------

def load_shared_secret_from_pem(station_id: str) -> bytes:
    """
    Lit keys/STxx_secret.pem et retourne le secret partagé (bytes).
    Format attendu :
    -----BEGIN STATION SHARED SECRET-----
    BASE64...
    -----END STATION SHARED SECRET-----
    """
    pem_path = os.path.join(KEYS_DIR, f"{station_id}_secret.pem")
    if not os.path.exists(pem_path):
        raise FileNotFoundError(f"Fichier PEM introuvable pour {station_id} : {pem_path}")

    with open(pem_path, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f.readlines()]

    # Extraire les lignes entre les balises BEGIN/END
    in_block = False
    b64_lines = []
    for line in lines:
        if line == "-----BEGIN STATION SHARED SECRET-----":
            in_block = True
            continue
        if line == "-----END STATION SHARED SECRET-----":
            break
        if in_block and line:
            b64_lines.append(line)

    if not b64_lines:
        raise ValueError(f"Aucun bloc BASE64 trouvé dans {pem_path}")

    b64_data = "".join(b64_lines)
    secret = base64.b64decode(b64_data)
    return secret


def derive_aes_key(shared_secret: bytes, station_id: str, salt: bytes) -> bytes:
    """
    Dérive une clé AES-256 à partir du secret partagé station↔auditeur + salt.
    On utilise HKDF(SHA-256).
    """
    info = f"odometer-{station_id}".encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,          # 32 octets = AES-256
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


# -----------------------------
# CRYPTO : chiffrer le record pour IPFS
# -----------------------------

def encrypt_record_for_ipfs(station_id: str, record: dict, shared_secret: bytes) -> dict:
    """
    - génère un salt aléatoire (public) pour cette transaction
    - dérive une clé AES à partir du secret + salt
    - chiffre le record (JSON) avec AES-GCM
    - retourne l'objet prêt à être envoyé à Pinata/IPFS
    """
    # 1) JSON -> bytes
    plaintext = json.dumps(record, ensure_ascii=False).encode("utf-8")

    # 2) salt (sel) pour HKDF (public)
    salt = os.urandom(16)

    # 3) dérivation clé AES
    aes_key = derive_aes_key(shared_secret, station_id, salt)

    # 4) AES-GCM : nonce + AAD
    nonce = os.urandom(12)  # recommandé pour GCM
    aad = f"odometer-record-v1|{station_id}".encode("utf-8")

    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    # 5) Objet IPFS (tous les champs encodés en base64)
    ipfs_obj = {
        "station_id": station_id,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "aad": base64.b64encode(aad).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return ipfs_obj


# -----------------------------
# PINATA : envoi JSON -> IPFS
# -----------------------------

def pin_json_to_pinata(payload: dict) -> str:
    """
    Envoie un objet JSON vers Pinata via pinJSONToIPFS.
    Retourne le CID (IpfsHash).
    """
    load_dotenv()
    PINATA_API_KEY = os.getenv("PINATA_API_KEY")
    PINATA_SECRET_API_KEY = os.getenv("PINATA_SECRET_API_KEY")

    if not PINATA_API_KEY or not PINATA_SECRET_API_KEY:
        raise RuntimeError("PINATA_API_KEY ou PINATA_SECRET_API_KEY manquant(s) dans .env")

    url = "https://api.pinata.cloud/pinning/pinJSONToIPFS"

    headers = {
        "Content-Type": "application/json",
        "pinata_api_key": PINATA_API_KEY,
        "pinata_secret_api_key": PINATA_SECRET_API_KEY,
    }

    resp = requests.post(url, headers=headers, data=json.dumps(payload))
    if not resp.ok:
        raise RuntimeError(f"Erreur Pinata: {resp.status_code} {resp.text}")

    data = resp.json()
    cid = data.get("IpfsHash")
    if not cid:
        raise RuntimeError(f"Réponse Pinata sans IpfsHash: {data}")
    return cid


# -----------------------------
# IOTA / IOTA EVM : ancrage du CID dans MileageLedger
# -----------------------------

def load_mileage_ledger_contract(w3: Web3):
    """
    Charge l'ABI du contrat MileageLedger depuis l'artifact Hardhat
    et retourne une instance de contrat Web3.
    L'adresse du contrat est lue dans l'env : MILEAGE_LEDGER_ADDRESS.
    """
    load_dotenv()
    contract_address = os.getenv("MILEAGE_LEDGER_ADDRESS")
    if not contract_address:
        raise RuntimeError("MILEAGE_LEDGER_ADDRESS manquante dans .env")

    if not os.path.exists(CONTRACT_ARTIFACT_PATH):
        raise FileNotFoundError(
            f"Artifact du contrat introuvable : {CONTRACT_ARTIFACT_PATH}\n"
            "Assure-toi d'avoir fait `npx hardhat compile` et d'être au bon endroit."
        )

    with open(CONTRACT_ARTIFACT_PATH, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    abi = artifact.get("abi")
    if not abi:
        raise RuntimeError("ABI introuvable dans l'artifact MileageLedger.")

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(contract_address),
        abi=abi
    )
    return contract


def anchor_in_iota(station_id: str,
                   record: dict,
                   cid: str,
                   private_key_hex: str) -> str:
    """
    Envoie une transaction à IOTA EVM pour appeler MileageLedger.recordMileage(
        vehicleId, timestamp, proofCid, odometerKm
    ), signée avec la PRIVATE_KEY de la station.
    Retourne le hash de la transaction.
    """
    load_dotenv()
    rpc_url = os.getenv("IOTA_RPC_URL")
    if not rpc_url:
        raise RuntimeError("IOTA_RPC_URL manquante dans .env")

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise RuntimeError(f"Impossible de se connecter à l'RPC IOTA : {rpc_url}")

    contract = load_mileage_ledger_contract(w3)

    # Clé privée et adresse de la station
    acct = w3.eth.account.from_key(private_key_hex)
    sender = acct.address

    # Préparation des paramètres pour recordMileage
    vehicle_id = record["vehicle_id"]
    timestamp = record["timestamp"]
    proof_cid = cid
    odometer_km = int(record["odometer_km"])

    # Construction de la transaction
    nonce = w3.eth.get_transaction_count(sender)
    chain_id = w3.eth.chain_id

    tx_function = contract.functions.recordMileage(
        vehicle_id,
        timestamp,
        proof_cid,
        odometer_km
    )

    gas_estimate = tx_function.estimate_gas({"from": sender})
    gas_limit = int(gas_estimate * 1.2)
    gas_price = w3.eth.gas_price

    tx = tx_function.build_transaction({
        "from": sender,
        "nonce": nonce,
        "gas": gas_limit,
        "gasPrice": gas_price,
        "chainId": chain_id,
    })

    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)

    return tx_hash.hex()


# -----------------------------
# MAIN : lancer une station
# -----------------------------

def main():
    if len(sys.argv) < 3:
        print("Usage : python station.py ST01 0xPRIVATE_KEY_STATION")
        sys.exit(1)

    station_id = sys.argv[1].strip().upper()
    private_key = sys.argv[2].strip()

    if station_id not in STATION_RECORDS:
        print(f"Station inconnue : {station_id}")
        print(f"Stations supportées : {', '.join(STATION_RECORDS.keys())}")
        sys.exit(1)

    # 1) Charger le secret partagé station↔auditeur
    shared_secret = load_shared_secret_from_pem(station_id)
    print(f"[{station_id}] Secret partagé chargé ({len(shared_secret)} octets).")

    # 2) Récupérer la liste des mesures pour CETTE station
    records = STATION_RECORDS[station_id]

    for base in records:   # base = un dict: {vehicle_id, odometer_km, source}
        # Construire un record COMPLET pour cette mesure
        record = {
            "station_id": station_id,
            "vehicle_id": base["vehicle_id"],
            "odometer_km": base["odometer_km"],
            "source": base["source"],
            "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        }
        print(f"[{station_id}] Record clair :", record)

        # 3) Chiffrer le record pour IPFS
        ipfs_obj = encrypt_record_for_ipfs(station_id, record, shared_secret)
        print(f"[{station_id}] Objet chiffré préparé pour IPFS.")

        # 4) Envoyer à Pinata et récupérer le CID
        cid = pin_json_to_pinata(ipfs_obj)
        print(f"[{station_id}] CID IPFS obtenu : {cid}")

        # 5) Ancrer dans IOTA (IOTA EVM) via MileageLedger
        try:
            tx_hash = anchor_in_iota(station_id, record, cid, private_key)
            print(f"[{station_id}] Transaction envoyée sur IOTA EVM : {tx_hash}\n\n")
            #print("   (appelle MileageLedger.recordMileage(vehicleId, timestamp, proofCid, odometerKm))")
        except Exception as e:
            print(f"[{station_id}] Erreur lors de l'ancrage dans IOTA : {e}")


if __name__ == "__main__":
    main()

