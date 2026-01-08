import path from "path";
import * as fs from "fs-extra";
import { utils, Wallet, Provider, EIP712Signer, types, Contract } from "zksync-ethers";
import { ethers } from "ethers";
import "dotenv/config";

// Utility function to read the compiled contract JSON
function readArtifactJson(rel: string) {
  const p = path.resolve(__dirname, "..", rel);
  if (!fs.existsSync(p)) throw new Error(`Artifact not found: ${p}`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function mustEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is missing in .env`);
  return v;
}

function loadEncryptedWallet(relPath: string, password: string, provider?: Provider) {
  const abs = path.resolve(__dirname, relPath);
  const encryptedJson = fs.readFileSync(abs, "utf8");
  const w = Wallet.fromEncryptedJsonSync(encryptedJson, password);
  return provider ? w.connect(provider) : w;
}

async function main() {
  const rpc = mustEnv("ZKSYNC_SEPOLIA_RPC_URL");
  const password = mustEnv("PRIVATE_KEY_PASSWORD");

  const accountAddr = mustEnv("ZK_ACCOUNT_ADDRESS");
  const tokenAddr = mustEnv("TOKEN_ADDRESS");
  const spender = mustEnv("SPENDER_ADDRESS");
  const amountStr = mustEnv("AMOUNT_TO_APPROVE");

  // Default encrypted key locations (adjust if you use ENV vars)
  const key1Path = process.env.ENCRYPTED_KEY_1_PATH ?? ".encryptedKey_1.json";
  const key2Path = process.env.ENCRYPTED_KEY_2_PATH ?? ".encryptedKey_2.json";

  const provider = new Provider(rpc);

  // Wallet only used for estimation/logging (any funded EOA works)
  const estimatorKeyPath = process.env.ENCRYPTED_KEY_PATH ?? key1Path;
  const estimator = loadEncryptedWallet(estimatorKeyPath, password, provider);

  console.log(`Estimator EOA: ${await estimator.getAddress()}`);
  console.log(`Smart account: ${accountAddr}`);

  // ERC20 ABI (from your repo artifacts)
  const erc20Artifact = readArtifactJson(
  "zkout/TestERC20.sol/TestERC20.json",
  "out/TestERC20.sol/TestERC20.json"
);

const erc20 = new Contract(tokenAddr, erc20Artifact.abi, provider);

  // Build ERC20 approve tx
  const amount = BigInt(amountStr);
  const txReq = await erc20.approve.populateTransaction(spender, amount);

  // Estimate gas
  const gasLimit = await provider.estimateGas({ ...txReq, from: estimator.address });
  const feeData = await provider.getFeeData();
  const gasPrice = feeData.gasPrice ?? (await provider.getGasPrice());

  const network = await provider.getNetwork();
  const nonce = await provider.getTransactionCount(accountAddr);

  // Build AA transaction (type 113)
  const aaTx: any = {
    ...txReq,
    from: accountAddr,
    gasLimit,
    gasPrice,
    chainId: network.chainId,
    nonce,
    type: 113,
    value: ethers.toBigInt(0),
    customData: {
      gasPerPubdata: utils.DEFAULT_GAS_PER_PUBDATA_LIMIT,
      // customSignature will be added below
    } as types.Eip712Meta,
  };

  // Load two owners (these should be the multisig owners)
  const owner1 = loadEncryptedWallet(key1Path, password);
  const owner2 = loadEncryptedWallet(key2Path, password);

  console.log(`Owner1 EOA: ${await owner1.getAddress()}`);
  console.log(`Owner2 EOA: ${await owner2.getAddress()}`);

  /**
   * IMPORTANT (alignment with your Solidity):
   * Your contract does:
   *   ethSignedHash = toEthSignedMessageHash(_suggestedSignedHash or computed hash)
   *
   * On zkSync, the bootloader provides suggestedSignedHash = EIP712 digest for AA txs.
   * So we must signMessage(digestBytes32), which applies the same prefix as toEthSignedMessageHash(bytes32).
   */
  const digest: string = EIP712Signer.getSignedDigest(aaTx); // bytes32 hex string

  const sig1 = await owner1.signMessage(ethers.getBytes(digest)); // 65 bytes
  const sig2 = await owner2.signMessage(ethers.getBytes(digest)); // 65 bytes

  // Contract expects raw concatenation of 65-byte sigs (NOT abi.encode(bytes[]))
  const multiSig = ethers.concat([sig1, sig2]);

  aaTx.customData = {
    ...aaTx.customData,
    customSignature: multiSig,
  };

  console.log(`Nonce before: ${await provider.getTransactionCount(accountAddr)}`);

  const serialized = types.Transaction.from(aaTx).serialized;
  const sent = await provider.broadcastTransaction(serialized);

  console.log(`AA tx hash: ${sent.hash}`);
  await sent.wait();

  console.log(`Nonce after:  ${await provider.getTransactionCount(accountAddr)}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

