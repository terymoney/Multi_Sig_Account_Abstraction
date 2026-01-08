// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { PackedUserOperation } from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { IEntryPoint } from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import { HelperConfig } from "script/HelperConfig.s.sol";
import { MultiSigAccountAbstraction } from "src/ethereum/MultiSigAccountAbstraction.sol";

contract SendPackedUserOp is Script {
    using MessageHashUtils for bytes32;

    function run() external {
        HelperConfig helperConfig = new HelperConfig();
        HelperConfig.NetworkConfig memory net = helperConfig.getActiveNetworkConfig();

        address accountAddr = vm.envAddress("ACCOUNT_ADDRESS");

        address token = vm.envAddress("TOKEN_ADDRESS");
        address spender = vm.envAddress("SPENDER_ADDRESS");
        uint256 amount = vm.envUint("AMOUNT_TO_APPROVE");

        bytes memory funcData = abi.encodeWithSelector(IERC20.approve.selector, spender, amount);
        bytes memory executeCalldata =
            abi.encodeWithSelector(MultiSigAccountAbstraction.execute.selector, token, 0, funcData);

        PackedUserOperation memory op = _getSignedOp(net.entryPoint, accountAddr, executeCalldata);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        // bundler/beneficiary can be owner1 for now
        uint256 bundlerKey = vm.envUint("PRIVATE_KEY_1");
        address payable beneficiary = payable(vm.addr(bundlerKey));

        vm.startBroadcast(bundlerKey);
        IEntryPoint(net.entryPoint).handleOps(ops, beneficiary);
        vm.stopBroadcast();
    }

    function _getSignedOp(
        address entryPoint,
        address sender,
        bytes memory callData
    )
        internal
        returns (PackedUserOperation memory)
    {
        PackedUserOperation memory op = _getUnsignedOp(sender, callData);

        bytes32 userOperationHash = IEntryPoint(entryPoint).getUserOpHash(op);
        bytes32 digest = userOperationHash.toEthSignedMessageHash();

        // Build multisig signature in a separate frame to avoid "stack too deep"
        op.signature = _build2of2Signature(digest);

        return op;
    }

    function _build2of2Signature(bytes32 digest) internal view returns (bytes memory) {
        // 2-of-2: take 2 signatures
        uint256 key1 = vm.envUint("PRIVATE_KEY_1");
        uint256 key2 = vm.envUint("PRIVATE_KEY_2");

        address signer1 = vm.addr(key1);
        address signer2 = vm.addr(key2);

        bytes memory sig1 = _sign(key1, digest);
        bytes memory sig2 = _sign(key2, digest);

        // Must be strictly increasing signer addresses
        bytes[] memory sigs = new bytes[](2);
        if (signer1 < signer2) {
            sigs[0] = sig1;
            sigs[1] = sig2;
        } else {
            sigs[0] = sig2;
            sigs[1] = sig1;
        }

        // Your spec: abi.encode(bytes[] signatures)
        return abi.encode(sigs);
    }

    function _sign(uint256 pk, bytes32 digest) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _getUnsignedOp(address sender, bytes memory callData) internal pure returns (PackedUserOperation memory) {
        uint128 verificationGasLimit = 1_000_000;
        uint128 callGasLimit = verificationGasLimit;

        uint128 maxPriorityFeePerGas = 1;
        uint128 maxFeePerGas = maxPriorityFeePerGas;

        return PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(uint256(verificationGasLimit) << 128 | callGasLimit),
            preVerificationGas: 1 << 24,
            gasFees: bytes32(uint256(maxPriorityFeePerGas) << 128 | maxFeePerGas),
            paymasterAndData: "",
            signature: ""
        });
    }
}
