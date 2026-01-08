// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Test } from "forge-std/Test.sol";
import { ZkMultiSigAccountAbstraction } from "src/zkSync/ZkMultiSigAccountAbstraction.sol";
import { MockERC20 } from "test/mocks/MockERC20.sol";

import {
    Transaction,
    MemoryTransactionHelper
} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/MemoryTransactionHelper.sol";

import { BOOTLOADER_FORMAL_ADDRESS } from "lib/foundry-era-contracts/src/system-contracts/contracts/Constants.sol";

import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {
    ACCOUNT_VALIDATION_SUCCESS_MAGIC
} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/IAccount.sol";

contract MockNonceHolder {
    // min nonce per account
    mapping(address => uint256) public minNonce;

    // allow tests to seed state after vm.etch
    function setMinNonce(address account, uint256 value) external {
        minNonce[account] = value;
    }

    // If current == expected: consume it and return expected
    // Else: return current (signals "rejected")
    function incrementMinNonceIfEquals(uint256 expected) external returns (uint256) {
        uint256 current = minNonce[msg.sender];

        if (current == expected) {
            unchecked {
                minNonce[msg.sender] = current + 1;
            }
            return expected;
        }

        return current;
    }
}

contract ZkMultiSigAccountAbstractionTest is Test {
    using MessageHashUtils for bytes32;

    uint256 constant PAY_FOR_TRANSACTION_VALUE = 1e18;
    uint8 constant ZKSYNC_AA_TX_TYPE = 0x71;

    ZkMultiSigAccountAbstraction public account;
    MockERC20 public mockERC20;

    address public owner1;
    uint256 public owner1Key;

    address public owner2;
    uint256 public owner2Key;

    // used by new tests (#7/#8)
    address public owner3;
    uint256 public owner3Key;

    // make randomUser signable
    address payable public randomUser;
    uint256 public randomUserKey;

    bytes32 constant EMPTY_BYTES32 = bytes32(0);

    // NonceHolder predeploy in zkSync Era
    address constant NONCE_HOLDER_SYSTEM_ADDR = address(uint160(0x8003));

    function setUp() public {
        mockERC20 = new MockERC20();

        (owner1, owner1Key) = makeAddrAndKey("owner1");
        (owner2, owner2Key) = makeAddrAndKey("owner2");

        (owner3, owner3Key) = makeAddrAndKey("owner3");

        (address ru, uint256 ruk) = makeAddrAndKey("randomUser");
        randomUser = payable(ru);
        randomUserKey = ruk;

        address[] memory owners = new address[](2);
        owners[0] = owner1;
        owners[1] = owner2;

        account = new ZkMultiSigAccountAbstraction(owners);

        vm.deal(address(account), PAY_FOR_TRANSACTION_VALUE);

        // etch mocked NonceHolder at 0x8003
        MockNonceHolder mockNonce = new MockNonceHolder();
        vm.etch(NONCE_HOLDER_SYSTEM_ADDR, address(mockNonce).code);

        // seed state at 0x8003 storage to match Foundry nonce for this account
        MockNonceHolder(NONCE_HOLDER_SYSTEM_ADDR).setMinNonce(address(account), vm.getNonce(address(account)));

        assertTrue(account.isOwner(owner1), "owner1 should be owner");
        assertTrue(account.isOwner(owner2), "owner2 should be owner");
    }

    /*//////////////////////////////////////////////////////////////
                      ORIGINAL 6 TESTS (yours)
    //////////////////////////////////////////////////////////////*/

    function testOwnersCanExecuteTransaction() public {
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory payload = abi.encodeWithSelector(MockERC20.mint.selector);

        Transaction memory tx_ = _getUnsignedTransaction(ZKSYNC_AA_TX_TYPE, dest, value, payload);

        bytes memory sig1 = _signatureFor(tx_, owner1Key);
        bytes memory sig2 = _signatureFor(tx_, owner2Key);

        tx_.signature = bytes.concat(sig1, sig2);
        assertEq(tx_.signature.length, 130, "need 2 signatures");

        vm.prank(owner1);
        account.executeTransactionFromOutside(tx_);

        assertEq(mockERC20.balanceOf(address(account)), mockERC20.AMOUNT());
    }

    function testReversedSignatureOrderAccepted() public {
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory payload = abi.encodeWithSelector(MockERC20.mint.selector);

        Transaction memory tx_ = _getUnsignedTransaction(ZKSYNC_AA_TX_TYPE, dest, value, payload);

        bytes memory sig1 = _signatureFor(tx_, owner1Key);
        bytes memory sig2 = _signatureFor(tx_, owner2Key);

        tx_.signature = bytes.concat(sig2, sig1);
        assertEq(tx_.signature.length, 130, "need 2 signatures");

        vm.prank(owner2);
        account.executeTransactionFromOutside(tx_);

        assertEq(mockERC20.balanceOf(address(account)), mockERC20.AMOUNT());
    }

    function testNonOwnerCannotCallExecuteTransaction() public {
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory payload = abi.encodeWithSelector(MockERC20.mint.selector);
        Transaction memory tx_ = _getUnsignedTransaction(ZKSYNC_AA_TX_TYPE, dest, value, payload);

        vm.prank(randomUser);
        vm.expectRevert();
        account.executeTransaction(EMPTY_BYTES32, EMPTY_BYTES32, tx_);
    }

    function testValidateTransactionReturnsMagic() public {
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory payload = abi.encodeWithSelector(MockERC20.mint.selector);

        Transaction memory tx_ = _getUnsignedTransaction(ZKSYNC_AA_TX_TYPE, dest, value, payload);

        bytes memory sig1 = _signatureFor(tx_, owner1Key);
        bytes memory sig2 = _signatureFor(tx_, owner2Key);

        tx_.signature = bytes.concat(sig1, sig2);
        assertEq(tx_.signature.length, 130, "need 2 signatures");

        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        bytes4 magic = account.validateTransaction(EMPTY_BYTES32, EMPTY_BYTES32, tx_);

        assertEq(magic, ACCOUNT_VALIDATION_SUCCESS_MAGIC);
    }

    function testSingleOwnerCannotExecuteTransaction() public {
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory payload = abi.encodeWithSelector(MockERC20.mint.selector);

        Transaction memory tx_ = _getUnsignedTransaction(ZKSYNC_AA_TX_TYPE, dest, value, payload);
        tx_.signature = _signatureFor(tx_, owner1Key);

        vm.prank(owner1);
        vm.expectRevert();
        account.executeTransactionFromOutside(tx_);
    }

    function testTamperedSignatureRejected() public {
        address dest = address(mockERC20);
        uint256 value = 0;
        bytes memory payload = abi.encodeWithSelector(MockERC20.mint.selector);

        Transaction memory tx_ = _getUnsignedTransaction(ZKSYNC_AA_TX_TYPE, dest, value, payload);

        bytes memory sig1 = _signatureFor(tx_, owner1Key);
        bytes memory sig2 = _signatureFor(tx_, owner2Key);

        bytes memory combo = bytes.concat(sig1, sig2);
        combo[combo.length - 1] = bytes1(uint8(combo[combo.length - 1]) ^ 0x01);
        tx_.signature = combo;

        vm.prank(owner1);
        vm.expectRevert();
        account.executeTransactionFromOutside(tx_);
    }

    /*//////////////////////////////////////////////////////////////
                    NEW TESTS #1 - #10 (ADDED)
    //////////////////////////////////////////////////////////////*/

    // 1) Reject signature length not multiple of 65
    function testRejectSignatureLengthNotMultipleOf65() public {
        Transaction memory tx0 = _getUnsignedTransaction(
            ZKSYNC_AA_TX_TYPE, address(mockERC20), 0, abi.encodeWithSelector(MockERC20.mint.selector)
        );

        tx0.signature = new bytes(64);

        vm.prank(owner1);
        vm.expectRevert();
        account.executeTransactionFromOutside(tx0);
    }

    // 2) Reject empty signature
    function testRejectEmptySignature() public {
        Transaction memory tx0 = _getUnsignedTransaction(
            ZKSYNC_AA_TX_TYPE, address(mockERC20), 0, abi.encodeWithSelector(MockERC20.mint.selector)
        );

        tx0.signature = hex"";

        vm.prank(owner1);
        vm.expectRevert();
        account.executeTransactionFromOutside(tx0);
    }

    // 3) Reject signatures with invalid v
    function testRejectInvalidV() public {
        Transaction memory tx0 = _getUnsignedTransaction(
            ZKSYNC_AA_TX_TYPE, address(mockERC20), 0, abi.encodeWithSelector(MockERC20.mint.selector)
        );

        bytes memory sig1 = _signatureFor(tx0, owner1Key);
        bytes memory sig2 = _signatureFor(tx0, owner2Key);

        bytes memory combo = bytes.concat(sig1, sig2);

        // v is last byte of first 65-byte sig => index 64
        combo[64] = bytes1(uint8(0));
        tx0.signature = combo;

        vm.prank(owner1);
        vm.expectRevert();
        account.executeTransactionFromOutside(tx0);
    }

    // 4) Reject non-owner signatures (both slots non-owner)
    function testRejectNonOwnerSignatures() public {
        Transaction memory tx0 = _getUnsignedTransaction(
            ZKSYNC_AA_TX_TYPE, address(mockERC20), 0, abi.encodeWithSelector(MockERC20.mint.selector)
        );

        bytes memory s1 = _signatureFor(tx0, randomUserKey);
        bytes memory s2 = _signatureFor(tx0, randomUserKey);

        tx0.signature = bytes.concat(s1, s2);

        vm.prank(owner1);
        vm.expectRevert();
        account.executeTransactionFromOutside(tx0);
    }

    // 5) Reject 1 owner + 1 non-owner
    function testRejectOwnerPlusNonOwner() public {
        Transaction memory tx0 = _getUnsignedTransaction(
            ZKSYNC_AA_TX_TYPE, address(mockERC20), 0, abi.encodeWithSelector(MockERC20.mint.selector)
        );

        bytes memory sOwner = _signatureFor(tx0, owner1Key);
        bytes memory sNon = _signatureFor(tx0, randomUserKey);

        tx0.signature = bytes.concat(sOwner, sNon);

        vm.prank(owner1);
        vm.expectRevert();
        account.executeTransactionFromOutside(tx0);
    }

    // 6) Reject duplicate owner signatures (owner1 twice)
    function testRejectDuplicateOwnerSignatures() public {
        Transaction memory tx0 = _getUnsignedTransaction(
            ZKSYNC_AA_TX_TYPE, address(mockERC20), 0, abi.encodeWithSelector(MockERC20.mint.selector)
        );

        bytes memory s1 = _signatureFor(tx0, owner1Key);
        tx0.signature = bytes.concat(s1, s1);

        vm.prank(owner1);
        vm.expectRevert();
        account.executeTransactionFromOutside(tx0);
    }

    // 7) Accept extra signatures beyond threshold (3 sigs, threshold=2)
    function testAcceptExtraSignaturesBeyondThreshold() public {
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        account.addOwner(owner3);
        assertTrue(account.isOwner(owner3), "owner3 should now be owner");

        Transaction memory tx0 = _getUnsignedTransaction(
            ZKSYNC_AA_TX_TYPE, address(mockERC20), 0, abi.encodeWithSelector(MockERC20.mint.selector)
        );

        bytes memory s1 = _signatureFor(tx0, owner1Key);
        bytes memory s2 = _signatureFor(tx0, owner2Key);
        bytes memory s3 = _signatureFor(tx0, owner3Key);

        tx0.signature = bytes.concat(s1, s2, s3);

        vm.prank(owner1);
        account.executeTransactionFromOutside(tx0);

        assertEq(mockERC20.balanceOf(address(account)), mockERC20.AMOUNT());
    }

    // 8) Accept different ordering with 3 signatures
    function testAcceptAnyOrderWithThreeSignatures() public {
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        account.addOwner(owner3);
        assertTrue(account.isOwner(owner3), "owner3 should now be owner");

        Transaction memory tx0 = _getUnsignedTransaction(
            ZKSYNC_AA_TX_TYPE, address(mockERC20), 0, abi.encodeWithSelector(MockERC20.mint.selector)
        );

        bytes memory s1 = _signatureFor(tx0, owner1Key);
        bytes memory s2 = _signatureFor(tx0, owner2Key);
        bytes memory s3 = _signatureFor(tx0, owner3Key);

        // order: owner3, owner1, owner2
        tx0.signature = bytes.concat(s3, s1, s2);

        vm.prank(owner2);
        account.executeTransactionFromOutside(tx0);

        assertEq(mockERC20.balanceOf(address(account)), mockERC20.AMOUNT());
    }

    // 9) Reject if any tx field changes after signing (example: change "to")
    function testRejectIfToChangesAfterSigning() public {
        Transaction memory tx0 = _getUnsignedTransaction(
            ZKSYNC_AA_TX_TYPE, address(mockERC20), 0, abi.encodeWithSelector(MockERC20.mint.selector)
        );

        bytes memory s1 = _signatureFor(tx0, owner1Key);
        bytes memory s2 = _signatureFor(tx0, owner2Key);

        // mutate after signing
        tx0.to = uint256(uint160(address(0xBEEF)));

        tx0.signature = bytes.concat(s1, s2);

        vm.prank(owner1);
        vm.expectRevert();
        account.executeTransactionFromOutside(tx0);
    }

    // 10) Suggested hash path:
    //     (a) correct suggestedSignedHash passes
    //     (b) wrong suggestedSignedHash reverts
    function testSuggestedHashPathCorrectAndWrong() public {
        Transaction memory tx0 = _getUnsignedTransaction(
            ZKSYNC_AA_TX_TYPE, address(mockERC20), 0, abi.encodeWithSelector(MockERC20.mint.selector)
        );

        // IMPORTANT: signatures in this suite sign ethSignedMessageHash(encodeHash(tx))
        // so suggestedSignedHash must be the raw txHash (encodeHash(tx)).
        bytes32 txHash0 = MemoryTransactionHelper.encodeHash(_txWithoutSig(tx0));

        bytes memory s1 = _signatureFor(tx0, owner1Key);
        bytes memory s2 = _signatureFor(tx0, owner2Key);
        tx0.signature = bytes.concat(s1, s2);

        // (a) correct suggested hash => magic
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        bytes4 magic = account.validateTransaction(EMPTY_BYTES32, txHash0, tx0);
        assertEq(magic, ACCOUNT_VALIDATION_SUCCESS_MAGIC);

        // nonce was consumed; build a fresh tx for wrong-hash case
        Transaction memory tx1 = _getUnsignedTransaction(
            ZKSYNC_AA_TX_TYPE, address(mockERC20), 0, abi.encodeWithSelector(MockERC20.mint.selector)
        );

        bytes32 realHash1 = MemoryTransactionHelper.encodeHash(_txWithoutSig(tx1));
        bytes memory t1s1 = _signatureFor(tx1, owner1Key);
        bytes memory t1s2 = _signatureFor(tx1, owner2Key);
        tx1.signature = bytes.concat(t1s1, t1s2);

        // (b) wrong suggested hash => should revert
        bytes32 wrongHash = keccak256(abi.encodePacked("wrong", realHash1));

        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        vm.expectRevert();
        account.validateTransaction(EMPTY_BYTES32, wrongHash, tx1);
    }

    /*//////////////////////////////////////////////////////////////
                    NEW TESTS #11 - #20
    //////////////////////////////////////////////////////////////*/

    // 11) validateTransaction must revert if caller is NOT bootloader
    function testValidateTransactionRevertsIfNotBootloader() public {
        address dest = address(mockERC20);
        bytes memory payload = abi.encodeWithSelector(MockERC20.mint.selector);

        Transaction memory tx0 = _getUnsignedTransaction(ZKSYNC_AA_TX_TYPE, dest, 0, payload);

        bytes memory sig1 = _signatureFor(tx0, owner1Key);
        bytes memory sig2 = _signatureFor(tx0, owner2Key);
        tx0.signature = bytes.concat(sig1, sig2);

        vm.prank(owner1); // not bootloader
        vm.expectRevert();
        account.validateTransaction(EMPTY_BYTES32, EMPTY_BYTES32, tx0);
    }

    // 12) addOwner must revert if caller is NOT bootloader
    function testAddOwnerRevertsIfNotBootloader() public {
        (address newOwner,) = makeAddrAndKey("newOwner");
        vm.prank(owner1);
        vm.expectRevert();
        account.addOwner(newOwner);
    }

    // 13) addOwner twice should revert (or at least fail)
    function testAddOwnerTwiceReverts() public {
        (address newOwner,) = makeAddrAndKey("newOwner2");

        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        account.addOwner(newOwner);
        assertTrue(account.isOwner(newOwner), "newOwner should be owner after add");

        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        vm.expectRevert();
        account.addOwner(newOwner);
    }

    // 14) Reject high-s malleable signature (if ECDSA checks are enforced)
    function testRejectHighSSignature() public {
        address dest = address(mockERC20);
        bytes memory payload = abi.encodeWithSelector(MockERC20.mint.selector);

        Transaction memory tx0 = _getUnsignedTransaction(ZKSYNC_AA_TX_TYPE, dest, 0, payload);

        bytes memory sig1 = _signatureFor(tx0, owner1Key);
        bytes memory sig2 = _signatureFor(tx0, owner2Key);

        // overwrite s of sig1 with a very large value to trigger ECDSAInvalidSignatureS()
        // sig layout: r(32) | s(32) | v(1)
        for (uint256 i = 32; i < 64; i++) {
            sig1[i] = 0xFF;
        }

        tx0.signature = bytes.concat(sig1, sig2);

        vm.prank(owner1);
        vm.expectRevert();
        account.executeTransactionFromOutside(tx0);
    }

    // 15) Reject correct-length but garbage signatures (random r/s/v bytes)
    function testRejectGarbageSignatures() public {
        address dest = address(mockERC20);
        bytes memory payload = abi.encodeWithSelector(MockERC20.mint.selector);

        Transaction memory tx0 = _getUnsignedTransaction(ZKSYNC_AA_TX_TYPE, dest, 0, payload);

        bytes memory garbage1 = new bytes(65);
        bytes memory garbage2 = new bytes(65);

        // Make them non-zero so it's not the "empty signature" case
        for (uint256 i = 0; i < 65; i++) {
            garbage1[i] = bytes1(uint8(i + 1));
            garbage2[i] = bytes1(uint8(i + 100));
        }

        tx0.signature = bytes.concat(garbage1, garbage2);

        vm.prank(owner1);
        vm.expectRevert();
        account.executeTransactionFromOutside(tx0);
    }

    // 16) Replay protection: executing the same signed tx twice must fail
    function testReplaySameTransactionFails() public {
        address dest = address(mockERC20);
        bytes memory payload = abi.encodeWithSelector(MockERC20.mint.selector);

        Transaction memory tx0 = _getUnsignedTransaction(ZKSYNC_AA_TX_TYPE, dest, 0, payload);

        bytes memory sig1 = _signatureFor(tx0, owner1Key);
        bytes memory sig2 = _signatureFor(tx0, owner2Key);
        tx0.signature = bytes.concat(sig1, sig2);

        vm.prank(owner1);
        account.executeTransactionFromOutside(tx0);
        assertEq(mockERC20.balanceOf(address(account)), mockERC20.AMOUNT());

        // replay exact same tx (same nonce) => should revert
        vm.prank(owner1);
        vm.expectRevert();
        account.executeTransactionFromOutside(tx0);
    }

    // 17) Reject if nonce is too far in the future
    function testRejectFutureNonce() public {
        address dest = address(mockERC20);
        bytes memory payload = abi.encodeWithSelector(MockERC20.mint.selector);

        Transaction memory tx0 = _getUnsignedTransaction(ZKSYNC_AA_TX_TYPE, dest, 0, payload);

        // mutate nonce forward, then sign THAT mutated tx
        tx0.nonce = tx0.nonce + 5;

        bytes memory sig1 = _signatureFor(tx0, owner1Key);
        bytes memory sig2 = _signatureFor(tx0, owner2Key);
        tx0.signature = bytes.concat(sig1, sig2);

        vm.prank(owner1);
        vm.expectRevert();
        account.executeTransactionFromOutside(tx0);
    }

    // 18) validateTransaction consumes nonce: calling validate twice with same tx should fail
    function testValidateTransactionReplayFails() public {
        address dest = address(mockERC20);
        bytes memory payload = abi.encodeWithSelector(MockERC20.mint.selector);

        Transaction memory tx0 = _getUnsignedTransaction(ZKSYNC_AA_TX_TYPE, dest, 0, payload);

        bytes memory sig1 = _signatureFor(tx0, owner1Key);
        bytes memory sig2 = _signatureFor(tx0, owner2Key);
        tx0.signature = bytes.concat(sig1, sig2);

        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        bytes4 magic = account.validateTransaction(EMPTY_BYTES32, EMPTY_BYTES32, tx0);
        assertEq(magic, ACCOUNT_VALIDATION_SUCCESS_MAGIC);

        // same tx again (same nonce) should revert
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        vm.expectRevert();
        account.validateTransaction(EMPTY_BYTES32, EMPTY_BYTES32, tx0);
    }

    // 19) executeTransaction should be callable by SELF (address(account)) path
    function testExecuteTransactionCallableBySelf() public {
        address dest = address(mockERC20);
        bytes memory payload = abi.encodeWithSelector(MockERC20.mint.selector);

        Transaction memory tx0 = _getUnsignedTransaction(ZKSYNC_AA_TX_TYPE, dest, 0, payload);

        bytes memory sig1 = _signatureFor(tx0, owner1Key);
        bytes memory sig2 = _signatureFor(tx0, owner2Key);
        tx0.signature = bytes.concat(sig1, sig2);

        // call executeTransaction as the account itself
        vm.prank(address(account));
        account.executeTransaction(EMPTY_BYTES32, EMPTY_BYTES32, tx0);

        assertEq(mockERC20.balanceOf(address(account)), mockERC20.AMOUNT());
    }

    // 20) Value transfer: send ETH out using `value`
    function testOwnersCanExecuteEthTransferValue() public {
        uint256 sendValue = 0.1 ether;
        address dest = address(randomUser);
        bytes memory payload = hex"";

        uint256 beforeBal = randomUser.balance;

        Transaction memory tx0 = _getUnsignedTransaction(ZKSYNC_AA_TX_TYPE, dest, sendValue, payload);

        bytes memory sig1 = _signatureFor(tx0, owner1Key);
        bytes memory sig2 = _signatureFor(tx0, owner2Key);
        tx0.signature = bytes.concat(sig1, sig2);

        vm.prank(owner1);
        account.executeTransactionFromOutside(tx0);

        assertEq(randomUser.balance, beforeBal + sendValue, "randomUser should receive ETH");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _getUnsignedTransaction(
        uint8 txType,
        address to,
        uint256 value,
        bytes memory data
    )
        internal
        view
        returns (Transaction memory)
    {
        uint256 nonce = vm.getNonce(address(account));
        bytes32[] memory factoryDeps = new bytes32[](0);

        return Transaction({
            txType: txType,
            from: uint256(uint160(address(account))), // AA account is sender
            to: uint256(uint160(to)),
            gasLimit: 1 << 24,
            gasPerPubdataByteLimit: 1 << 24,
            maxFeePerGas: 1 << 24,
            maxPriorityFeePerGas: 1 << 24,
            paymaster: 0,
            nonce: nonce,
            value: value,
            reserved: [uint256(0), uint256(0), uint256(0), uint256(0)],
            data: data,
            signature: hex"",
            factoryDeps: factoryDeps,
            paymasterInput: hex"",
            reservedDynamic: hex""
        });
    }

    function _txWithoutSig(Transaction memory tx_) internal pure returns (Transaction memory) {
        Transaction memory tmp = tx_;
        tmp.signature = hex"";
        return tmp;
    }

    // Returns a 65-byte signature without mutating caller.
    // Matches contract validation: recover( toEthSignedMessageHash(encodeHash(tx)) )
    function _signatureFor(Transaction memory tx_, uint256 privateKey) internal view returns (bytes memory) {
        Transaction memory tmp = _txWithoutSig(tx_);
        bytes32 txHash = MemoryTransactionHelper.encodeHash(tmp);
        bytes32 digest = txHash.toEthSignedMessageHash();

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
