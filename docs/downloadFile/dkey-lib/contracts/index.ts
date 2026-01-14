import DKeyStoreL2Contract from './DKeyStoreL2.json';
import DividendPayingTokenContract from './DividendPayingToken.json';

export const contracts = {
  DKeyStoreL2: {
    1: {
      abi: DKeyStoreL2Contract.abi,
      address: '0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9' as `0x${string}`,  // TODO: deploy to mainnet
      deploymentBlockNumber: 1, // block number of contract deployment
      chainName: 'Ethereum',
    },
    8453: {
      abi: DKeyStoreL2Contract.abi,
      address: '0xD1B5B4483aBEF82eC5063210603231954fE1c628' as `0x${string}`, // test contract uploaded to base
      deploymentBlockNumber: 40483908, // block number of contract deployment
      chainName: 'Base',
    },
  },
  DividendPayingToken: {
    31337: {
      abi: DividendPayingTokenContract.abi,
      address: '0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9' as `0x${string}`,
      deploymentBlockNumber: 1, // block number of contract deployment
      chainName: 'Hardhat',
    },
  },
};

export default contracts;