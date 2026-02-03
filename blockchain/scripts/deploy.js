async function main() {
  console.log("Déploiement du contrat MileageLedger sur IOTA testnet...");
  const MileageLedger = await ethers.getContractFactory("MileageLedger");
  const ledger = await MileageLedger.deploy();
  await ledger.waitForDeployment();
  const address = await ledger.getAddress();
  console.log("Contrat déployé à l’adresse :", address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("Erreur de déploiement :", error);
    process.exit(1);
  });
