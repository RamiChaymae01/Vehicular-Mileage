// @ts-nocheck
require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

const PRIVATE_KEY = process.env.PRIVATE_KEY;

if (!PRIVATE_KEY) {
  console.error("PRIVATE_KEY non trouvé dans .env !");
  process.exit(1);
}

module.exports = {
  solidity: "0.8.20",
  defaultNetwork: "iota_testnet",
  networks: {
    hardhat: {},
    iota_testnet: {
      url: "https://json-rpc.evm.testnet.iota.cafe",
      accounts: [PRIVATE_KEY]
    }
  }
};
