````md
# Minimal Account Abstraction (EVM ERC-4337 + zkSync Native AA)

A portfolio project demonstrating **Account Abstraction** across two ecosystems:

1) **EVM AA (ERC-4337-style / alt-mempool flow)**  
   - Deploy + verify AA contracts on **Ethereum Sepolia**
   - Work with AA patterns around EntryPoint/UserOperation-style execution (EVM track)

2) **zkSync Era Native AA**  
   - Deploy a native AA smart account on **zkSync Era Sepolia**
   - Deploy a test ERC20, mint, approve spending, and transfer tokens (zkSync track)

This repo is built to show real deployment + interaction workflows, not just theory.

---

## Why Account Abstraction?

Traditional Web3 transactions originate from EOAs controlled by a single private key.  
Account Abstraction allows **smart contracts to behave like accounts**, enabling:

- multi-owner / multisig authorization flows
- programmable spending rules and validation logic
- better UX patterns (batching, sponsorship, recovery concepts)

This project demonstrates those concepts in code and on-chain deployments.

---

## What this repo demonstrates

### ✅ EVM Track (Ethereum Sepolia)
- AA contract deployment and **verification on Etherscan**
- EVM AA workflow foundation (ERC-4337-style patterns)

### ✅ zkSync Track (zkSync Era Sepolia)
- Native AA smart account deployment (ZkMultiSigAccountAbstraction)
- Test ERC20 deployment + minting
- ERC20 approve + transfer (including funding the AA smart account with tokens)

---

## Live Deployments (Portfolio Proof)

### Ethereum Sepolia (Verified)
- **Contract:** https://sepolia.etherscan.io/address/0x063643dc5708fDcd8C52e99F1f696f73B7125cfb  
- **Deployment tx:** https://sepolia.etherscan.io/tx/0x052fc5d8a14fda0f85937b86e17ed1816ab5254685337577f92ba1f26c8a2608  

### zkSync Era Sepolia
- **AA Smart Account:**  
  (https://sepolia.explorer.zksync.io/address/0x8B24BCc2568C840fd79AB3e4a8F497e00e7A6b1B)

- **TestERC20:**  
  https://sepolia.explorer.zksync.io/address/0xea20A883eB092D7f6B6a9579600FE1443018b82E

- **Example zkSync txs (demo proof):**
  - Mint:    https://sepolia.explorer.zksync.io/tx/0xfa2b7ff18034662f8360e7b3069d330916d2e888b353cd7f13ecbbf0e72db7d9
  - Approve: https://sepolia.explorer.zksync.io/tx/0xc3c1978400438a00c30097a1651c12235d638ce1913640a9c7b3b2d56f82e85c
  - Transfer:https://sepolia.explorer.zksync.io/tx/0x4e0cbc7f68c6a62405dc2382aa7f6f9764b3af0dbec26ca9c9aeb6d66878e869

---

## Repository Layout

### Solidity / Foundry (EVM track)
Typical folders in this repo:
- `src/MultiSigAccountAbstraction.sol` — Solidity contracts (EVM AA contracts)
- `script/DeployMultiSigAccountAbstraction.s.sol` — Foundry deployment scripts (EVM deployments)
- `test/MultiSigAccountAbstractionTest.t.sol` — Foundry tests

### TypeScript scripts (zkSync track)
- `javascript-scripts/DeployZkMinimal.ts` — deploy zkSync AA account
- `javascript-scripts/DeployERC20.ts` — deploy Test ERC20 on zkSync
- `javascript-scripts/ApproveAndTransfer.ts` — approve + optional transfer (EOA signer)

Env file used by TS scripts:
- `/$ROOTFOLDER/.env`

Env file used by TS scripts:
- `javascript-scripts/.env`

> Note: Foundry scripts handle the EVM track, while `javascript-scripts/` handle zkSync deployments/interactions.

---

# Getting Started

## Requirements
- Node.js 18+
- npm
- Foundry (`cast`, `forge`)

## Install
```bash
npm install
````

## Load environment

```bash
set -a
source javascript-scripts/.env
set +a
```

---

# Quickstart

## A) EVM Track (Ethereum Sepolia)

> Use this track for your EVM AA contracts (ERC-4337 style).

### Build + test

```bash
forge build
forge test
```

### Deploy (example)

```bash
# Replace with your repo's actual deploy script name if different
forge script script/Deploy.s.sol --rpc-url $SEPOLIA_RPC_URL --broadcast --private-key $PRIVATE_KEY_1
```

### Verify

```bash
# If you used forge verify-contract before, keep that workflow here.
# Replace CONTRACT_NAME + constructor args as needed.
forge verify-contract \
  --chain-id 11155111 \
  --compiler-version v0.8.24 \
  <SEPOLIA_DEPLOYMENT_ADDRESS> \
  src/<CONTRACT_FILE>.sol:<CONTRACT_NAME> \
  --etherscan-api-key $ETHERSCAN_API_KEY
```

---

## B) zkSync Track (zkSync Era Sepolia)

### 1) Deploy zkSync AA smart account

```bash
npx tsx javascript-scripts/DeployZkMinimal.ts
```

Set address in env:

```bash
sed -i 's/^ZK_ACCOUNT_ADDRESS=.*/ZK_ACCOUNT_ADDRESS=0x8B24BCc2568C840fd79AB3e4a8F497e00e7A6b1B/' javascript-scripts/.env
set -a && source javascript-scripts/.env && set +a
```

Sanity checks:

```bash
cast codesize $ZK_ACCOUNT_ADDRESS --rpc-url $ZKSYNC_SEPOLIA_RPC_URL
cast balance  $ZK_ACCOUNT_ADDRESS --rpc-url $ZKSYNC_SEPOLIA_RPC_URL
```

### 2) Deploy ERC20

```bash
npx tsx javascript-scripts/DeployERC20.ts
```

Set token address:

```bash
sed -i 's/^TOKEN_ADDRESS=.*/TOKEN_ADDRESS=0xea20A883eB092D7f6B6a9579600FE1443018b82E/' javascript-scripts/.env
set -a && source javascript-scripts/.env && set +a
```

### 3) Mint tokens to EOA

```bash
cast send $TOKEN_ADDRESS \
  "mint(address,uint256)" \
  $EOA1 \
  1000000000000000000000 \
  --private-key $PRIVATE_KEY_1 \
  --rpc-url $ZKSYNC_SEPOLIA_RPC_URL
```

### 4) Approve spender

```bash
cast send $TOKEN_ADDRESS \
  "approve(address,uint256)" \
  $SPENDER_ADDRESS \
  $AMOUNT_TO_APPROVE \
  --private-key $PRIVATE_KEY_1 \
  --rpc-url $ZKSYNC_SEPOLIA_RPC_URL
```

Check allowance:

```bash
cast call $TOKEN_ADDRESS \
  "allowance(address,address)(uint256)" \
  $EOA1 $SPENDER_ADDRESS \
  --rpc-url $ZKSYNC_SEPOLIA_RPC_URL
```

### 5) Transfer tokens to the AA smart account (fund it)

```bash
# recipient = AA contract
sed -i 's/^RECIPIENT_ADDRESS=.*/RECIPIENT_ADDRESS='"$ZK_ACCOUNT_ADDRESS"'/' javascript-scripts/.env 2>/dev/null || \
echo "RECIPIENT_ADDRESS=$ZK_ACCOUNT_ADDRESS" >> javascript-scripts/.env

# transfer 10 tokens (18 decimals)
sed -i 's/^TRANSFER_AMOUNT=.*/TRANSFER_AMOUNT=10000000000000000000/' javascript-scripts/.env 2>/dev/null || \
echo "TRANSFER_AMOUNT=10000000000000000000" >> javascript-scripts/.env

set -a && source javascript-scripts/.env && set +a

cast send $TOKEN_ADDRESS \
  "transfer(address,uint256)" \
  $RECIPIENT_ADDRESS $TRANSFER_AMOUNT \
  --private-key $PRIVATE_KEY_1 \
  --rpc-url $ZKSYNC_SEPOLIA_RPC_URL
```

Verify balances:

```bash
cast call $TOKEN_ADDRESS "balanceOf(address)(uint256)" $EOA1 --rpc-url $ZKSYNC_SEPOLIA_RPC_URL
cast call $TOKEN_ADDRESS "balanceOf(address)(uint256)" $ZK_ACCOUNT_ADDRESS --rpc-url $ZKSYNC_SEPOLIA_RPC_URL
```

---

## zkSync Verification (optional)


---

## Author

**Maria Terese Ezeobi**

---

## Disclaimer

This project is for educational/portfolio demonstration purposes and has not undergone a security audit.

```
