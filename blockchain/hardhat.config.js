// @ts-nocheck
// IoTa
/*
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
*/

// @ts-nocheck
require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

const PRIVATE_KEY = process.env.PRIVATE_KEY;
const SEPOLIA_RPC_URL = process.env.SEPOLIA_RPC_URL;
const AMOY_RPC_URL = process.env.AMOY_RPC_URL;
const BSC_TESTNET_RPC_URL = process.env.BSC_TESTNET_RPC_URL;

if (!PRIVATE_KEY) {
  console.error("PRIVATE_KEY non trouvé dans .env !");
  process.exit(1);
}

if (!SEPOLIA_RPC_URL) {
  console.error("SEPOLIA_RPC_URL non trouvé dans .env !");
  process.exit(1);
}

if (!AMOY_RPC_URL) {
  console.error("AMOY_RPC_URL non trouvé dans .env !");
  process.exit(1);
}

if (!BSC_TESTNET_RPC_URL) {
  console.error("BSC_TESTNET_RPC_URL non trouvé dans .env !");
  process.exit(1);
}

module.exports = {
  solidity: "0.8.20",

  networks: {
    hardhat: {},

    iota_testnet: {
      url: "https://json-rpc.evm.testnet.iota.cafe",
      accounts: [PRIVATE_KEY]
    },

    sepolia: {
      url: SEPOLIA_RPC_URL,
      accounts: [PRIVATE_KEY]
    },

    amoy: {
      url: AMOY_RPC_URL,
      accounts: [PRIVATE_KEY],
      chainId: 80002
    },

    bsc_testnet: {
      url: BSC_TESTNET_RPC_URL,
      accounts: [PRIVATE_KEY],
      chainId: 97
    }
  }
};