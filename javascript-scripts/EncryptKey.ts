import { ethers } from "ethers";
import * as fs from "fs-extra";
import "dotenv/config";

async function encryptAndWrite(pkEnvName: "PRIVATE_KEY_1" | "PRIVATE_KEY_2", outFile: string) {
  const pk = process.env[pkEnvName];
  const password = process.env.PRIVATE_KEY_PASSWORD;

  if (!pk) throw new Error(`${pkEnvName} is missing in .env`);
  if (!password) throw new Error(`PRIVATE_KEY_PASSWORD is missing in .env`);

  const wallet = new ethers.Wallet(pk);
  const encryptedJsonKey = await wallet.encrypt(password);

  fs.writeFileSync(outFile, encryptedJsonKey);
  console.log(`${pkEnvName} encrypted for address: ${wallet.address}`);
  console.log(`Saved: ${outFile}`);
}

async function main() {
  await encryptAndWrite("PRIVATE_KEY_1", "./.encryptedKey_1.json");
  await encryptAndWrite("PRIVATE_KEY_2", "./.encryptedKey_2.json");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
