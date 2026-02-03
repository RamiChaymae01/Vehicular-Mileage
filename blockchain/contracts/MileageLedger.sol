// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MileageLedger {
    // =========================================================
    //  ÉTAT
    // =========================================================
    address public owner;

    // Dernier kilométrage cohérent par véhicule
    mapping(bytes32 => uint256) private lastOdometerByVehicle;

    // Flag global de fraude par véhicule (true si rollback déjà détecté)
    mapping(bytes32 => bool) private fraudFlagByVehicle;

    // Historique complet des enregistrements
    struct MileageRecord {
        string vehicleId;    // ID pseudonymisé
        string timestamp;    // ISO 8601
        string proofCid;     // CID IPFS de la preuve chiffrée
        uint256 odometerKm;  // valeur stockée (après logique anti-rollback)
        uint8 fraud;         // 0 = sain, 1 = véhicule marqué frauduleux
    }

    MileageRecord[] public records;

    // =========================================================
    //  EVENTS
    // =========================================================

    event ContractDeployed(address indexed contractAddress);

    // Enregistrement normal (pour indexation off-chain)
    event MileageRecorded(
        bytes32 indexed vehicleKey,
        string vehicleId,
        string timestamp,
        string proofCid,
        uint256 odometerKm,
        uint8 fraud
    );

    // Rollback détecté : on logge la tentative
    event FraudDetected(
        string vehicleId,
        uint256 lastValidKm,
        uint256 attemptedKm
    );

    // 🔍 Event de debug : ancienne valeur, valeur demandée, nouvelle valeur stockée, flags de fraude
    event MileageDebug(
        string vehicleId,
        uint256 previousOdometerKm,
        uint256 requestedOdometerKm,
        uint256 newStoredOdometerKm,
        uint8 previousFraudFlag,
        uint8 newFraudFlag
    );

    // =========================================================
    //  MODIFIER
    // =========================================================

    modifier onlyOwner() {
        require(msg.sender == owner, "Not contract owner");
        _;
    }

    // =========================================================
    //  CONSTRUCTEUR
    // =========================================================

    constructor() {
        owner = msg.sender;
        emit ContractDeployed(address(this));
    }

    // =========================================================
    //  LOGIQUE PRINCIPALE
    // =========================================================

    /// @notice Enregistre une nouvelle mesure de kilometrage pour un vehicule.
    /// @dev Applique la logique anti-rollback et met a jour le flag de fraude.
    function recordMileage(
        string calldata vehicleId,
        string calldata timestamp,
        string calldata proofCid,
        uint256 odometerKm
    ) external {
        // Clé hashée pour les mappings
        bytes32 key = keccak256(bytes(vehicleId));

        // Valeur avant cet enregistrement
        uint256 prev = lastOdometerByVehicle[key];
        bool prevFraudBool = fraudFlagByVehicle[key];
        uint8 prevFraudFlag = prevFraudBool ? 1 : 0;

        // Valeurs qui seront effectivement stockées dans l'historique
        uint256 storedKm = odometerKm;
        uint8 newFraudFlag = prevFraudFlag;

        // ==========================
        // 1 Détection de rollback
        // ==========================
        if (prev > 0 && odometerKm < prev) {
            // Rollback detecte : on marque le vehicule comme frauduleux
            fraudFlagByVehicle[key] = true;
            newFraudFlag = 1;

            // On ne descend jamais : on garde la derniere valeur coherente
            storedKm = prev;

            emit FraudDetected(vehicleId, prev, odometerKm);

        } else {
            // ==========================
            // 2 Pas de rollback
            // ==========================
            // Si c'est la premiere mesure (prev == 0) ou une valeur plus grande, on met a jour
            if (prev == 0 || odometerKm > prev) {
                lastOdometerByVehicle[key] = odometerKm;
            }

            // Si le vehicule a été marqué frauduleux entre-temps, on force à 1
            if (fraudFlagByVehicle[key]) {
                newFraudFlag = 1;
            }
        }

        // ==========================
        // 3 Enregistrement historique
        // ==========================
        records.push(
            MileageRecord({
                vehicleId: vehicleId,
                timestamp: timestamp,
                proofCid: proofCid,
                odometerKm: storedKm,
                fraud: newFraudFlag
            })
        );

        emit MileageRecorded(
            key,
            vehicleId,
            timestamp,
            proofCid,
            storedKm,
            newFraudFlag
        );

        // ==========================
        // 4 Event de debug (pour voir ce qui se passe a chaque appel)
        // ==========================
        emit MileageDebug(
            vehicleId,
            prev,           // ancienne valeur stockée
            odometerKm,     // valeur demandée par la station
            storedKm,       // valeur finalement stockée (prev si rollback, sinon odometerKm)
            prevFraudFlag,  // flag de fraude AVANT cet enregistrement
            newFraudFlag    // flag de fraude APRES cet enregistrement
        );
    }

    // =========================================================
    //  FONCTIONS DE LECTURE
    // =========================================================

    /// @notice Retourne un enregistrement historique par index.
    function getRecord(uint256 index)
        external
        view
        returns (
            string memory vehicleId,
            string memory timestamp,
            string memory proofCid,
            uint256 odometerKm,
            uint8 fraud
        )
    {
        require(index < records.length, "Index out of bounds");
        MileageRecord storage r = records[index];
        return (r.vehicleId, r.timestamp, r.proofCid, r.odometerKm, r.fraud);
    }

    /// @notice Nombre total d'enregistrements dans l'historique.
    function getCount() external view returns (uint256) {
        return records.length;
    }

    /// @notice Dernier kilometrage coherent pour un vehicule.
    function getLastOdometerKm(string calldata vehicleId)
        external
        view
        returns (uint256)
    {
        bytes32 key = keccak256(bytes(vehicleId));
        return lastOdometerByVehicle[key];
    }

    /// @notice Flag global de fraude pour un vehicule.
    function getFraudFlag(string calldata vehicleId)
        external
        view
        returns (bool)
    {
        bytes32 key = keccak256(bytes(vehicleId));
        return fraudFlagByVehicle[key];
    }
}
