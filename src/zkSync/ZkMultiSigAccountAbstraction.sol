// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {
    IAccount,
    ACCOUNT_VALIDATION_SUCCESS_MAGIC
} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/IAccount.sol";

import {
    Transaction,
    MemoryTransactionHelper
} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/MemoryTransactionHelper.sol";

import {
    BOOTLOADER_FORMAL_ADDRESS,
    NONCE_HOLDER_SYSTEM_CONTRACT,
    DEPLOYER_SYSTEM_CONTRACT
} from "lib/foundry-era-contracts/src/system-contracts/contracts/Constants.sol";

import {
    SystemContractsCaller
} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/SystemContractsCaller.sol";

import { INonceHolder } from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/INonceHolder.sol";
import { Utils } from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/Utils.sol";

import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title ZkMultiSigAccountAbstraction
 * @author Maria Terese Nmachi Ezeobi
 * @notice 2-of-N multisignature Account Abstraction wallet for zkSync Era.
 *
 * @dev
 * Implements zkSync native Account Abstraction (`IAccount`).
 * Transactions are validated using ECDSA signatures from at least two
 * distinct owners and protected against replay via the zkSync NonceHolder
 * system contract.
 *
 * Signature rules:
 * - Signatures are over `toEthSignedMessageHash(encodeHash(tx))`
 * - Order-independent
 * - Duplicate and non-owner signatures are rejected
 *
 * @custom:chain zkSync Era
 */
contract ZkMultiSigAccountAbstraction is IAccount {
    error ZkMultiSigAccountAbstraction__NotFromBootloader();
    error ZkMultiSigAccountAbstraction__NotFromBootloaderOrSelf();
    error ZkMultiSigAccountAbstraction__InvalidOwner();
    error ZkMultiSigAccountAbstraction__OwnerAlreadyExists(address owner);
    error ZkMultiSigAccountAbstraction__OwnerDoesNotExist(address owner);
    error ZkMultiSigAccountAbstraction__OwnersTooFew();
    error ZkMultiSigAccountAbstraction__InvalidSignature();
    error ZkMultiSigAccountAbstraction__ExecutionFailed();
    error ZkMultiSigAccountAbstraction__InvalidNonce(uint256 expected, uint256 got);

    uint256 public constant THRESHOLD = 2;

    mapping(address => bool) private s_isOwner;
    address[] private s_owners;

    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);

    modifier onlyBootloader() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS) revert ZkMultiSigAccountAbstraction__NotFromBootloader();
        _;
    }

    modifier requireFromBootloaderOrSelf() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS && msg.sender != address(this)) {
            revert ZkMultiSigAccountAbstraction__NotFromBootloaderOrSelf();
        }
        _;
    }

    constructor(address[] memory owners) {
        if (owners.length < THRESHOLD) revert ZkMultiSigAccountAbstraction__OwnersTooFew();

        for (uint256 i = 0; i < owners.length; i++) {
            address ownerAddr = owners[i];
            if (ownerAddr == address(0)) revert ZkMultiSigAccountAbstraction__InvalidOwner();
            if (s_isOwner[ownerAddr]) revert ZkMultiSigAccountAbstraction__OwnerAlreadyExists(ownerAddr);

            s_isOwner[ownerAddr] = true;
            s_owners.push(ownerAddr);
            emit OwnerAdded(ownerAddr);
        }
    }

    /*//////////////////////////////////////////////////////////////
                          OWNER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function addOwner(address newOwner) external requireFromBootloaderOrSelf {
        if (newOwner == address(0)) revert ZkMultiSigAccountAbstraction__InvalidOwner();
        if (s_isOwner[newOwner]) revert ZkMultiSigAccountAbstraction__OwnerAlreadyExists(newOwner);

        s_isOwner[newOwner] = true;
        s_owners.push(newOwner);
        emit OwnerAdded(newOwner);
    }

    function removeOwner(address ownerToRemove) external requireFromBootloaderOrSelf {
        if (!s_isOwner[ownerToRemove]) revert ZkMultiSigAccountAbstraction__OwnerDoesNotExist(ownerToRemove);

        uint256 ownerCount = s_owners.length;
        if (ownerCount <= THRESHOLD) revert ZkMultiSigAccountAbstraction__OwnersTooFew();

        s_isOwner[ownerToRemove] = false;

        for (uint256 i = 0; i < ownerCount; i++) {
            if (s_owners[i] == ownerToRemove) {
                s_owners[i] = s_owners[ownerCount - 1];
                s_owners.pop();
                break;
            }
        }

        emit OwnerRemoved(ownerToRemove);
    }

    function isOwner(address addr) external view returns (bool) {
        return s_isOwner[addr];
    }

    function getOwners() external view returns (address[] memory) {
        return s_owners;
    }

    function getOwnerCount() external view returns (uint256) {
        return s_owners.length;
    }

    /*//////////////////////////////////////////////////////////////
                       INTERNAL VALIDATION & EXECUTION
    //////////////////////////////////////////////////////////////*/

    function _safeGas32() internal view returns (uint32) {
        uint256 g = gasleft();
        return g > type(uint32).max ? type(uint32).max : uint32(g);
    }

    function _consumeNonceOrRevert(uint256 nonce) internal {
        address nonceAddr = address(NONCE_HOLDER_SYSTEM_CONTRACT);
        bytes memory incCalldata = abi.encodeCall(INonceHolder.incrementMinNonceIfEquals, (nonce));

        // We want BOTH:
        // - correct zkSync behavior (systemCall) when running on Era
        // - test friendliness (call/etch) on local EVM forks
        (bool ok, bytes memory ret) = nonceAddr.call(incCalldata);
        if (!ok) {
            // This path will revert with the exact reason from the system contract
            SystemContractsCaller.systemCallWithPropagatedRevert(_safeGas32(), nonceAddr, 0, incCalldata);
            // unreachable
        }

        // On zkSync, INonceHolder.incrementMinNonceIfEquals returns the accepted nonce (uint256).
        // If the nonce is rejected (replay or gap), it returns something != `nonce`.
        // In a test, your mock must also follow this rule for replay/future-nonce tests to work.
        if (ret.length >= 32) {
            uint256 accepted = abi.decode(ret, (uint256));
            if (accepted != nonce) revert ZkMultiSigAccountAbstraction__InvalidNonce(nonce, accepted);
        } else {
            // Defensive: if a mock returns nothing, treat as failure
            revert ZkMultiSigAccountAbstraction__InvalidNonce(nonce, 0);
        }
    }

    function _validateTransaction(
        bytes32 _suggestedSignedHash,
        Transaction calldata _transaction
    )
        internal
        returns (bytes4)
    {
        // 1) Consume nonce (replay + future/gap protection)
        _consumeNonceOrRevert(_transaction.nonce);

        // 2) Resolve tx hash (never hash the signature)
        bytes32 txHash;
        if (_suggestedSignedHash != bytes32(0)) {
            txHash = _suggestedSignedHash;
        } else {
            Transaction memory txCopy = _transaction;
            txCopy.signature = hex"";
            txHash = MemoryTransactionHelper.encodeHash(txCopy);
        }

        // 3) Ethereum signed message hash
        bytes32 ethSignedHash = MessageHashUtils.toEthSignedMessageHash(txHash);

        // 4) Parse signatures: accept any order, reject duplicates, require THRESHOLD unique owner sigs
        bytes memory sig = _transaction.signature;

        // Reject empty, reject non-multiple-of-65
        if (sig.length == 0 || sig.length % 65 != 0) revert ZkMultiSigAccountAbstraction__InvalidSignature();

        uint256 sigCount = sig.length / 65;
        uint256 validSignatures = 0;
        address[] memory seen = new address[](sigCount);

        for (uint256 i = 0; i < sigCount; i++) {
            bytes32 r;
            bytes32 s;
            uint8 v;

            assembly {
                let base := add(sig, add(32, mul(i, 65)))
                r := mload(base)
                s := mload(add(base, 32))
                v := byte(0, mload(add(base, 64)))
            }

            // OZ ECDSA enforces:
            // - v must be 27 or 28
            // - s must be in lower half order (anti-malleability)
            address signer = ECDSA.recover(ethSignedHash, v, r, s);

            if (!s_isOwner[signer]) revert ZkMultiSigAccountAbstraction__InvalidSignature();

            // reject duplicates
            for (uint256 j = 0; j < validSignatures; j++) {
                if (seen[j] == signer) revert ZkMultiSigAccountAbstraction__InvalidSignature();
            }

            seen[validSignatures] = signer;
            validSignatures++;

            if (validSignatures == THRESHOLD) {
                return ACCOUNT_VALIDATION_SUCCESS_MAGIC;
            }
        }

        revert ZkMultiSigAccountAbstraction__InvalidSignature();
    }

    function _executeTransaction(Transaction calldata _transaction) internal {
        address to = address(uint160(_transaction.to));
        uint128 value = Utils.safeCastToU128(_transaction.value);
        bytes memory data = _transaction.data;

        if (to == address(DEPLOYER_SYSTEM_CONTRACT)) {
            uint32 gasLimit = _safeGas32();
            SystemContractsCaller.systemCallWithPropagatedRevert(gasLimit, to, value, data);
        } else {
            (bool success,) = to.call{ value: value }(data);
            if (!success) revert ZkMultiSigAccountAbstraction__ExecutionFailed();
        }
    }

    /*//////////////////////////////////////////////////////////////
                          IAccount IMPLEMENTATION
    //////////////////////////////////////////////////////////////*/

    function validateTransaction(
        bytes32,
        bytes32 _suggestedSignedHash,
        Transaction calldata _transaction
    )
        external
        payable
        override
        onlyBootloader
        returns (bytes4)
    {
        return _validateTransaction(_suggestedSignedHash, _transaction);
    }

    function executeTransaction(
        bytes32,
        bytes32,
        Transaction calldata _transaction
    )
        external
        payable
        override
        requireFromBootloaderOrSelf
    {
        _executeTransaction(_transaction);
    }

    function executeTransactionFromOutside(Transaction calldata _transaction) external payable {
        bytes4 magic = _validateTransaction(bytes32(0), _transaction);
        require(magic == ACCOUNT_VALIDATION_SUCCESS_MAGIC, "Multisig validation failed");
        _executeTransaction(_transaction);
    }

    function payForTransaction(
        bytes32,
        bytes32,
        Transaction calldata _transaction
    )
        external
        payable
        override
        onlyBootloader
    {
        // NOTE: This is simplified/test-friendly. zkSync fee logic is more complex in production.
        uint256 requiredFee = _transaction.value;
        (bool success,) = BOOTLOADER_FORMAL_ADDRESS.call{ value: requiredFee }("");
        if (!success) revert ZkMultiSigAccountAbstraction__ExecutionFailed();
    }

    function prepareForPaymaster(bytes32, bytes32, Transaction calldata) external payable override onlyBootloader {
        // no-op
    }

    fallback() external {
        if (msg.sender == BOOTLOADER_FORMAL_ADDRESS) {
            revert ZkMultiSigAccountAbstraction__NotFromBootloader();
        }
    }

    receive() external payable { }
}
