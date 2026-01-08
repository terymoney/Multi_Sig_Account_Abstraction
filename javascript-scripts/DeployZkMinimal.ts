import path from "path";
import * as fs from "fs-extra";
import { Wallet, Provider, ContractFactory } from "zksync-ethers";
import "dotenv/config";

function mustEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`${name} is missing in .env`);
  return v;
}

function readJson(rel: string) {
  const p = path.resolve(__dirname, "..", rel);
  if (!fs.existsSync(p)) throw new Error(`Artifact not found: ${p}`);
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

function getByPath(obj: any, p: string): any {
  return p.split(".").reduce((acc, k) => acc?.[k], obj);
}

function normalizeHexBytecode(bc: string): string {
  // some artifacts store bytecode without 0x
  if (!bc.startsWith("0x")) bc = "0x" + bc;
  return bc;
}

/**
 * Try the common places zkSync / solc / foundry artifacts store bytecode.
 * We intentionally do NOT treat bytecodeHash/factoryDeps as deploy bytecode.
 */
function extractBytecode(artifact: any): string {
  const candidates = [
    "bytecode",
    "bytecode.object",
    "evm.bytecode.object",
    "evm.bytecode",
    "data.bytecode",
    "zk.bytecode",
  ];

  for (const p of candidates) {
    const v = getByPath(artifact, p);
    if (typeof v === "string" && v.length > 0) {
      const hex = normalizeHexBytecode(v);
      // sanity check
      if (hex === "0x") continue;
      return hex;
    }
  }

  // If we get here, print a helpful hint
  const topKeys = Object.keys(artifact ?? {});
  throw new Error(
    `Bytecode not found in artifact JSON.
Tried: ${candidates.join(", ")}
Top-level keys found: ${topKeys.join(", ")}

Make sure you're reading the zkSync-compiled artifact in zkout/, e.g.
  zkout/ZkMultiSigAccountAbstraction.sol/ZkMultiSigAccountAbstraction.json`
  );
}

async function main() {
  const rpc = mustEnv("ZKSYNC_SEPOLIA_RPC_URL");
  const password = mustEnv("PRIVATE_KEY_PASSWORD");

  const provider = new Provider(rpc);

  const enc1Path = path.resolve(__dirname, ".encryptedKey_1.json");
  const enc2Path = path.resolve(__dirname, ".encryptedKey_2.json");

  const wallet1 = Wallet.fromEncryptedJsonSync(fs.readFileSync(enc1Path, "utf8"), password).connect(provider);
  const wallet2 = Wallet.fromEncryptedJsonSync(fs.readFileSync(enc2Path, "utf8"), password).connect(provider);

  const owner1 = await wallet1.getAddress();
  const owner2 = await wallet2.getAddress();

  console.log(`Deploying with owners:\n  owner1: ${owner1}\n  owner2: ${owner2}`);
  console.log(`Deployer balance (owner1): ${(await provider.getBalance(owner1)).toString()}`);

  // IMPORTANT: zkSync artifact from zkout/
  const artifact = readJson("zkout/ZkMultiSigAccountAbstraction.sol/ZkMultiSigAccountAbstraction.json");

  const abi = artifact?.abi;
  if (!abi) throw new Error("ABI not found in artifact JSON");

  const bytecode = extractBytecode(artifact);

  const factory = new ContractFactory(abi, bytecode, wallet1);
  const deployed = await factory.deploy([owner1, owner2]);
  await deployed.waitForDeployment();

  const addr = await deployed.getAddress();
  console.log(`ZkMultiSigAccountAbstraction deployed to: ${addr}`);
  console.log(`Now set: ZK_ACCOUNT_ADDRESS=${addr} in your .env`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
