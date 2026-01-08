// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// ERC-4337 / Account Abstraction
import { IAccount } from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
import { IEntryPoint } from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS } from "lib/account-abstraction/contracts/core/Helpers.sol";

// OpenZeppelin
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @author Maria Terese Nmachi Ezeobi
/// @title MultiSigAccountAbstraction
/// @notice ERC-4337 account with fixed 2-of-N multisig validation.
/// @dev userOp.signature MUST be: abi.encode(bytes[] signatures)
///      - at least 2 signatures
///      - recovered signer addresses must be strictly increasing (sorted ascending)
///      - all signers must be owners
///      - owner management is ONLY callable via EntryPoint-executed calls (UserOp), not by EOAs directly.
contract MultiSigAccountAbstraction is IAccount {
    using MessageHashUtils for bytes32;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/
    error MultiSigAA__NotFromEntryPoint();
    error MultiSigAA__NotFromEntryPointOrSelf();
    error MultiSigAA__InvalidEntryPoint();
    error MultiSigAA__InvalidOwner();
    error MultiSigAA__OwnerAlreadyExists(address owner);
    error MultiSigAA__OwnerDoesNotExist(address owner);
    error MultiSigAA__OwnersTooFew();
    error MultiSigAA__ExecutionFailed();

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/
    uint256 public constant THRESHOLD = 2;

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/
    IEntryPoint private immutable i_entryPoint;

    mapping(address => bool) private s_isOwner;
    address[] private s_owners;

    /*//////////////////////////////////////////////////////////////
                               EVENTS
    //////////////////////////////////////////////////////////////*/
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/
    modifier requireFromEntryPoint() {
        if (msg.sender != address(i_entryPoint)) revert MultiSigAA__NotFromEntryPoint();
        _;
    }

    /// @dev Only callable through a valid UserOp (EntryPoint) or via internal self-call.
    modifier requireFromEntryPointOrSelf() {
        if (msg.sender != address(i_entryPoint) && msg.sender != address(this)) {
            revert MultiSigAA__NotFromEntryPointOrSelf();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/
    constructor(address entryPointAddress, address[] memory owners) {
        if (entryPointAddress == address(0)) revert MultiSigAA__InvalidEntryPoint();
        if (owners.length < THRESHOLD) revert MultiSigAA__OwnersTooFew();

        i_entryPoint = IEntryPoint(entryPointAddress);

        for (uint256 i = 0; i < owners.length; i++) {
            address o = owners[i];
            if (o == address(0)) revert MultiSigAA__InvalidOwner();
            if (s_isOwner[o]) revert MultiSigAA__OwnerAlreadyExists(o);

            s_isOwner[o] = true;
            s_owners.push(o);
            emit OwnerAdded(o);
        }
    }

    receive() external payable { }

    /*//////////////////////////////////////////////////////////////
                    ERC-4337 ACCOUNT INTERFACE
    //////////////////////////////////////////////////////////////*/
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    )
        external
        override
        requireFromEntryPoint
        returns (uint256 validationData)
    {
        validationData = _validateSignature(userOp, userOpHash);
        _payPrefund(missingAccountFunds);
    }

    /// @notice Execute arbitrary call — only via UserOp (EntryPoint) or internal self-call.
    function execute(address dest, uint256 value, bytes calldata funcData) external requireFromEntryPointOrSelf {
        _execute(dest, value, funcData);
    }

    /*//////////////////////////////////////////////////////////////
                     OWNER MGMT (UserOp-only)
    //////////////////////////////////////////////////////////////*/
    function addOwner(address newOwner) external requireFromEntryPointOrSelf {
        if (newOwner == address(0)) revert MultiSigAA__InvalidOwner();
        if (s_isOwner[newOwner]) revert MultiSigAA__OwnerAlreadyExists(newOwner);

        s_isOwner[newOwner] = true;
        s_owners.push(newOwner);
        emit OwnerAdded(newOwner);
    }

    function removeOwner(address ownerToRemove) external requireFromEntryPointOrSelf {
        if (!s_isOwner[ownerToRemove]) revert MultiSigAA__OwnerDoesNotExist(ownerToRemove);
        if (s_owners.length <= THRESHOLD) revert MultiSigAA__OwnersTooFew(); // can't go below 2 owners

        s_isOwner[ownerToRemove] = false;

        // swap & pop
        uint256 len = s_owners.length;
        for (uint256 i = 0; i < len; i++) {
            if (s_owners[i] == ownerToRemove) {
                s_owners[i] = s_owners[len - 1];
                s_owners.pop();
                break;
            }
        }

        emit OwnerRemoved(ownerToRemove);
    }

    /*//////////////////////////////////////////////////////////////
                              VIEWS
    //////////////////////////////////////////////////////////////*/
    function entryPoint() external view returns (IEntryPoint) {
        return i_entryPoint;
    }

    function isOwner(address who) external view returns (bool) {
        return s_isOwner[who];
    }

    function getOwners() external view returns (address[] memory) {
        return s_owners;
    }

    function getDeposit() external view returns (uint256) {
        return i_entryPoint.balanceOf(address(this));
    }

    function addDeposit() external payable {
        i_entryPoint.depositTo{ value: msg.value }(address(this));
    }

    /*//////////////////////////////////////////////////////////////
                    INTERNAL: SIGNATURE VALIDATION
    //////////////////////////////////////////////////////////////*/
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        internal
        view
        returns (uint256)
    {
        // Required: abi.encode(bytes[] signatures)
        bytes[] memory sigs = abi.decode(userOp.signature, (bytes[]));
        if (sigs.length < THRESHOLD) return SIG_VALIDATION_FAILED;

        bytes32 digest = userOpHash.toEthSignedMessageHash();

        // Require strictly increasing signer addresses (sorted) => prevents duplicates cheaply.
        address last = address(0);
        uint256 valid = 0;

        for (uint256 i = 0; i < sigs.length; i++) {
            if (sigs[i].length != 65) return SIG_VALIDATION_FAILED;

            address signer = ECDSA.recover(digest, sigs[i]);

            if (signer <= last) return SIG_VALIDATION_FAILED; // unsorted or duplicate
            last = signer;

            if (!s_isOwner[signer]) return SIG_VALIDATION_FAILED;

            valid++;
            if (valid == THRESHOLD) return SIG_VALIDATION_SUCCESS;
        }

        return SIG_VALIDATION_FAILED;
    }

    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{ value: missingAccountFunds }("");
            (success);
        }
    }

    function _execute(address dest, uint256 value, bytes memory funcData) internal {
        (bool success, bytes memory result) = dest.call{ value: value }(funcData);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }
}
