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

// zkout stores bytecode as: { bytecode: { object: "...." } } with NO 0x prefix
function extractZkoutBytecode(artifact: any): string {
  const obj = artifact?.bytecode?.object;

  if (typeof obj !== "string" || obj.length === 0) {
    throw new Error(
      `Bytecode not found in artifact.bytecode.object.\n` +
        `Keys: ${Object.keys(artifact || {}).join(", ")}\n` +
        `bytecode keys: ${artifact?.bytecode ? Object.keys(artifact.bytecode).join(", ") : "null"}`
    );
  }

  // Prefix 0x if missing
  return obj.startsWith("0x") ? obj : `0x${obj}`;
}

async function main() {
  const rpc = mustEnv("ZKSYNC_SEPOLIA_RPC_URL");
  const password = mustEnv("PRIVATE_KEY_PASSWORD");

  const provider = new Provider(rpc);

  const enc1Path = path.resolve(__dirname, ".encryptedKey_1.json");
  const wallet = Wallet.fromEncryptedJsonSync(fs.readFileSync(enc1Path, "utf8"), password).connect(provider);

  const deployer = await wallet.getAddress();
  console.log(`Deployer: ${deployer}`);
  console.log(`Deployer balance: ${(await provider.getBalance(deployer)).toString()}`);

  // IMPORTANT: must use zkout/ artifact (built by forge build --zksync --skip test)
  const artifact = readJson("zkout/TestERC20.sol/TestERC20.json");

  const abi = artifact.abi;
  if (!abi) throw new Error("ABI not found in artifact");

  const bytecode = extractZkoutBytecode(artifact);

  // Your constructor args: name + symbol
  const name = "TestCoin";
  const symbol = "TC";

  const factory = new ContractFactory(abi, bytecode, wallet);
  const deployed = await factory.deploy(name, symbol);

  const addr = await deployed.getAddress();
  console.log(`TestERC20 deployed to: ${addr}`);
  console.log(`Now set: TOKEN_ADDRESS=${addr} in your .env`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
