import { JsonRpcProvider, utils } from 'ethers';

async function main() {
  const RPC_URL = process.env.ZKSYNC_SEPOLIA_RPC_URL;

  const provider = new JsonRpcProvider(RPC_URL);  // use `JsonRpcProvider` directly
  const PRIVATE_KEY = process.env.PRIVATE_KEY_1;
  const wallet = new ethers.Wallet(PRIVATE_KEY, provider);

  const TOKEN_ADDRESS = process.env.TOKEN_ADDRESS;
  const SPENDER_ADDRESS = process.env.SPENDER_ADDRESS;
  const amount = utils.parseUnits("100", 18);  // Ensure we're using ethers.utils

  console.log("Wallet Address:", wallet.address);

  const token = new ethers.Contract(TOKEN_ADDRESS, ERC20_ABI, wallet);

  // Approve transaction
  const approveTx = await token.approve(SPENDER_ADDRESS, amount);
  console.log("Approval Tx Hash:", approveTx.hash);
  await approveTx.wait();

  console.log("Tokens approved for spending!");
}

main().catch(console.error);
