// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Test } from "forge-std/Test.sol";
import { MultiSigAccountAbstraction } from "src/ethereum/MultiSigAccountAbstraction.sol";
import { MockERC20 } from "test/mocks/MockERC20.sol";
import { MockEntryPoint, PackedUserOperation } from "test/mocks/MockEntryPoint.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {
    PackedUserOperation as LibPackedUserOperation
} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";

contract MultiSigAccountAbstractionTest is Test {
    using MessageHashUtils for bytes32;

    MockEntryPoint entryPoint;
    MultiSigAccountAbstraction account;
    MockERC20 token;

    address owner1;
    uint256 ownerKey1;
    address owner2;
    uint256 ownerKey2;

    address payable beneficiary;

    function setUp() public {
        // Deploy local mocks
        entryPoint = new MockEntryPoint();
        token = new MockERC20();

        // Two EOAs (your multisig owners)
        (owner1, ownerKey1) = makeAddrAndKey("owner1");
        (owner2, ownerKey2) = makeAddrAndKey("owner2");

        // Owners must be unique and can be in any order for storage,
        // BUT our signature verification requires signatures be sorted by signer address.
        address[] memory owners = new address[](2);
        owners[0] = owner1;
        owners[1] = owner2;

        account = new MultiSigAccountAbstraction(address(entryPoint), owners);

        beneficiary = payable(makeAddr("beneficiary"));
    }

    function testEOACannotExecuteDirectly() public {
        // In your security model, execute is NOT callable by EOAs directly.
        vm.prank(owner1);
        vm.expectRevert(); // requireFromEntryPointOrSelf
        account.execute(address(token), 0, abi.encodeWithSelector(MockERC20.mint.selector));
    }

    function testUserOpWithTwoSignaturesCanExecute() public {
        // Arrange: calldata that makes the AA account call token.mint()
        bytes memory callData = abi.encodeWithSelector(
            MultiSigAccountAbstraction.execute.selector,
            address(token),
            0,
            abi.encodeWithSelector(MockERC20.mint.selector)
        );

        PackedUserOperation memory op = _getSignedUserOp(callData);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        // Account must have ETH to pay prefund since no paymaster
        vm.deal(address(account), 1e18);

        // Act: any bundler can call handleOps
        entryPoint.handleOps(ops, beneficiary);

        // Assert: mint happened, balance is credited to the AA account
        assertEq(token.balanceOf(address(account)), token.AMOUNT());
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/
    function _getSignedUserOp(bytes memory callData) internal view returns (PackedUserOperation memory) {
        PackedUserOperation memory op = _getUnsignedUserOp(callData);

        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        bytes32 digest = userOpHash.toEthSignedMessageHash();

        // Sign with both owners
        bytes memory sig1 = _sign(ownerKey1, digest);
        bytes memory sig2 = _sign(ownerKey2, digest);

        // Sort signatures by recovered signer address (strictly increasing rule)
        address s1 = vm.addr(ownerKey1);
        address s2 = vm.addr(ownerKey2);

        bytes[] memory sigs = new bytes[](2);
        if (s1 < s2) {
            sigs[0] = sig1;
            sigs[1] = sig2;
        } else {
            sigs[0] = sig2;
            sigs[1] = sig1;
        }

        // Your spec: abi.encode(bytes[] signatures)
        op.signature = abi.encode(sigs);
        return op;
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _getUnsignedUserOp(bytes memory callData) internal view returns (PackedUserOperation memory) {
        uint128 verificationGasLimit = 1 << 24;
        uint128 callGasLimit = 1 << 24;

        uint128 maxPriorityFeePerGas = 1 << 8;
        uint128 maxFeePerGas = 1 << 8;

        return PackedUserOperation({
            sender: address(account),
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

    /*//////////////////////////////////////////////////////////////
                           MORE TESTS
    //////////////////////////////////////////////////////////////*/

    function testValidateUserOpOnlyCallableByEntryPoint() public {
        LibPackedUserOperation memory op; // empty is fine; modifier reverts before use

        vm.expectRevert(MultiSigAccountAbstraction.MultiSigAA__NotFromEntryPoint.selector);
        account.validateUserOp(op, bytes32(0), 0);
    }

    function testUserOpFailsWithOneSignature() public {
        bytes memory callData = abi.encodeWithSelector(
            MultiSigAccountAbstraction.execute.selector,
            address(token),
            0,
            abi.encodeWithSelector(MockERC20.mint.selector)
        );

        PackedUserOperation memory op = _getUnsignedUserOp(callData);

        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        bytes32 digest = userOpHash.toEthSignedMessageHash();

        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(ownerKey1, digest);
        op.signature = abi.encode(sigs);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.deal(address(account), 1e18);

        vm.expectRevert(); // signature error path inside MockEntryPoint
        entryPoint.handleOps(ops, beneficiary);
    }

    function testUserOpFailsWithUnsortedSignatures() public {
        // Arrange: calldata that makes the AA account call token.mint()
        bytes memory callData = abi.encodeWithSelector(
            MultiSigAccountAbstraction.execute.selector,
            address(token),
            0,
            abi.encodeWithSelector(MockERC20.mint.selector)
        );

        // Build an unsigned op
        PackedUserOperation memory op = _getUnsignedUserOp(callData);

        // Hash + EIP-191 digest (same path your account validates)
        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        bytes32 digest = userOpHash.toEthSignedMessageHash();

        // Sign with both owners
        bytes memory sig1 = _sign(ownerKey1, digest);
        bytes memory sig2 = _sign(ownerKey2, digest);

        // Force UNSORTED signatures: put the LARGER signer address first
        address a1 = vm.addr(ownerKey1);
        address a2 = vm.addr(ownerKey2);

        bytes[] memory sigs = new bytes[](2);
        if (a1 < a2) {
            // correct sorted would be sig1, sig2 — so invert it
            sigs[0] = sig2;
            sigs[1] = sig1;
        } else {
            // correct sorted would be sig2, sig1 — so invert it
            sigs[0] = sig1;
            sigs[1] = sig2;
        }

        op.signature = abi.encode(sigs);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        // Prefund
        vm.deal(address(account), 1e18);

        // Act + Assert: invalid signature ordering -> validate fails -> EntryPoint reverts
        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);
    }

    function testUserOpFailsWithDuplicateSigner() public {
        bytes memory callData = abi.encodeWithSelector(
            MultiSigAccountAbstraction.execute.selector,
            address(token),
            0,
            abi.encodeWithSelector(MockERC20.mint.selector)
        );

        PackedUserOperation memory op = _getUnsignedUserOp(callData);

        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        bytes32 digest = userOpHash.toEthSignedMessageHash();

        bytes memory sig1 = _sign(ownerKey1, digest);

        // Duplicate signer -> signer <= last fails on 2nd signature
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = sig1;
        sigs[1] = sig1;
        op.signature = abi.encode(sigs);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.deal(address(account), 1e18);

        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);
    }

    function testUserOpFailsWithNonOwnerSignature() public {
        bytes memory callData = abi.encodeWithSelector(
            MultiSigAccountAbstraction.execute.selector,
            address(token),
            0,
            abi.encodeWithSelector(MockERC20.mint.selector)
        );

        PackedUserOperation memory op = _getUnsignedUserOp(callData);

        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        bytes32 digest = userOpHash.toEthSignedMessageHash();

        // attacker is NOT an owner
        (, uint256 attackerKey) = makeAddrAndKey("attacker");

        bytes memory sigOwner = _sign(ownerKey1, digest);
        bytes memory sigAttacker = _sign(attackerKey, digest);

        // Keep signatures sorted by signer address so failure is due to "not owner", not sorting
        bytes[] memory sigs = new bytes[](2);
        address sOwner = vm.addr(ownerKey1);
        address sAtt = vm.addr(attackerKey);

        if (sOwner < sAtt) {
            sigs[0] = sigOwner;
            sigs[1] = sigAttacker;
        } else {
            sigs[0] = sigAttacker;
            sigs[1] = sigOwner;
        }

        op.signature = abi.encode(sigs);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.deal(address(account), 1e18);

        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);
    }

    function testReplaySameUserOpFailsOnNonce() public {
        bytes memory callData = abi.encodeWithSelector(
            MultiSigAccountAbstraction.execute.selector,
            address(token),
            0,
            abi.encodeWithSelector(MockERC20.mint.selector)
        );

        PackedUserOperation memory op = _getSignedUserOp(callData);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.deal(address(account), 1e18);

        // First time succeeds
        entryPoint.handleOps(ops, beneficiary);

        // Second time with SAME nonce (0) must fail
        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);
    }

    function testUserOpFailsWithBadSigLength() public {
        bytes memory callData = abi.encodeWithSelector(
            MultiSigAccountAbstraction.execute.selector,
            address(token),
            0,
            abi.encodeWithSelector(MockERC20.mint.selector)
        );

        PackedUserOperation memory op = _getUnsignedUserOp(callData);
        bytes32 userOpHash = entryPoint.getUserOpHash(op);
        bytes32 digest = userOpHash.toEthSignedMessageHash();

        bytes memory sig1 = _sign(ownerKey1, digest);

        // make it 64 bytes instead of 65
        bytes memory badSig = new bytes(64);
        for (uint256 i = 0; i < 64; i++) {
            badSig[i] = sig1[i];
        }

        // Provide two sigs but one is invalid length
        bytes[] memory sigs = new bytes[](2);

        sigs[0] = badSig;
        sigs[1] = sig1;

        op.signature = abi.encode(sigs);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.deal(address(account), 1e18);

        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);
    }

    function testAddOwnerOnlyEntryPointOrSelf() public {
        address newOwner = makeAddr("newOwner");

        // EOA cannot addOwner
        vm.prank(owner1);
        vm.expectRevert(MultiSigAccountAbstraction.MultiSigAA__NotFromEntryPointOrSelf.selector);
        account.addOwner(newOwner);

        // EntryPoint can addOwner (simulate UserOp route)
        vm.prank(address(entryPoint));
        account.addOwner(newOwner);

        assertTrue(account.isOwner(newOwner));
    }

    function testRemoveOwnerCannotGoBelowThreshold() public {
        // With exactly 2 owners, removing one should revert (OwnersTooFew)
        vm.prank(address(entryPoint));
        vm.expectRevert(MultiSigAccountAbstraction.MultiSigAA__OwnersTooFew.selector);
        account.removeOwner(owner1);
    }

    /*//////////////////////////////////////////////////////////////
                        ADDITIONAL TESTS: EXECUTION SAFETY
    //////////////////////////////////////////////////////////////*/

    function testExecuteCanSendEth() public {
        address payable receiver = payable(makeAddr("receiver"));
        vm.deal(address(account), 1 ether);

        // call execute(receiver, 0.4 ether, "")
        bytes memory callData =
            abi.encodeWithSelector(MultiSigAccountAbstraction.execute.selector, receiver, 0.4 ether, bytes(""));

        PackedUserOperation memory op = _getSignedUserOp(callData);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.deal(address(account), 1e18); // prefund too

        uint256 beforeBal = receiver.balance;
        entryPoint.handleOps(ops, beneficiary);
        assertEq(receiver.balance, beforeBal + 0.4 ether);
    }

    /*//////////////////////////////////////////////////////////////
                    ADDITIONAL TESTS: OWNER MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    function testConstructorRevertsOnDuplicateOwners() public {
        address[] memory owners = new address[](2);
        owners[0] = owner1;
        owners[1] = owner1;

        vm.expectRevert(
            abi.encodeWithSelector(MultiSigAccountAbstraction.MultiSigAA__OwnerAlreadyExists.selector, owner1)
        );
        new MultiSigAccountAbstraction(address(entryPoint), owners);
    }

    function testConstructorRevertsOnZeroOwner() public {
        address[] memory owners = new address[](2);
        owners[0] = owner1;
        owners[1] = address(0);

        vm.expectRevert(MultiSigAccountAbstraction.MultiSigAA__InvalidOwner.selector);
        new MultiSigAccountAbstraction(address(entryPoint), owners);
    }

    function testConstructorRevertsIfOwnersTooFew() public {
        address[] memory owners = new address[](1);
        owners[0] = owner1;

        vm.expectRevert(MultiSigAccountAbstraction.MultiSigAA__OwnersTooFew.selector);
        new MultiSigAccountAbstraction(address(entryPoint), owners);
    }

    function testAddOwnerRejectsZeroAddress() public {
        vm.prank(address(entryPoint));
        vm.expectRevert(MultiSigAccountAbstraction.MultiSigAA__InvalidOwner.selector);
        account.addOwner(address(0));
    }

    function testAddOwnerRejectsDuplicate() public {
        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigAccountAbstraction.MultiSigAA__OwnerAlreadyExists.selector, owner1)
        );
        account.addOwner(owner1);
    }

    function testRemoveOwnerRejectsNonOwner() public {
        address notOwner = makeAddr("notOwner");
        vm.prank(address(entryPoint));
        vm.expectRevert(
            abi.encodeWithSelector(MultiSigAccountAbstraction.MultiSigAA__OwnerDoesNotExist.selector, notOwner)
        );
        account.removeOwner(notOwner);
    }

    function testRemoveOwnerActuallyRemovesAndUpdatesIsOwner() public {
        // add a 3rd owner so we can remove one and still stay >= threshold
        address owner3 = makeAddr("owner3");
        vm.prank(address(entryPoint));
        account.addOwner(owner3);
        assertTrue(account.isOwner(owner3));

        vm.prank(address(entryPoint));
        account.removeOwner(owner3);

        assertFalse(account.isOwner(owner3));

        // sanity: owners array length decreased
        address[] memory owners = account.getOwners();
        assertEq(owners.length, 2);
    }

    function testRemoveOwnerSwapAndPopKeepsOtherOwners() public {
        // add two more owners so swap&pop is exercised more clearly
        address owner3 = makeAddr("owner3");
        address owner4 = makeAddr("owner4");

        vm.prank(address(entryPoint));
        account.addOwner(owner3);
        vm.prank(address(entryPoint));
        account.addOwner(owner4);

        // remove owner1 (existing original owner) — contract should swap&pop cleanly
        vm.prank(address(entryPoint));
        account.removeOwner(owner1);

        assertFalse(account.isOwner(owner1));
        assertTrue(account.isOwner(owner2));
        assertTrue(account.isOwner(owner3));
        assertTrue(account.isOwner(owner4));

        // length should be 3 now
        address[] memory owners = account.getOwners();
        assertEq(owners.length, 3);
    }

    /*//////////////////////////////////////////////////////////////
                ADDITIONAL TESTS: SIGNATURE HANDLING / THRESHOLD
    //////////////////////////////////////////////////////////////*/

    function testUserOpSucceedsWithMoreThanTwoSignaturesStillValid() public {
        // add a 3rd owner, then provide 3 sorted sigs; should still pass (stops at threshold=2)
        (address owner3, uint256 ownerKey3) = makeAddrAndKey("owner3");
        vm.prank(address(entryPoint));
        account.addOwner(owner3);

        bytes memory callData = abi.encodeWithSelector(
            MultiSigAccountAbstraction.execute.selector,
            address(token),
            0,
            abi.encodeWithSelector(MockERC20.mint.selector)
        );

        PackedUserOperation memory op = _getUnsignedUserOp(callData);
        bytes32 digest = entryPoint.getUserOpHash(op).toEthSignedMessageHash();

        // Sign with all 3 owners
        bytes memory sig1 = _sign(ownerKey1, digest);
        bytes memory sig2 = _sign(ownerKey2, digest);
        bytes memory sig3 = _sign(ownerKey3, digest);

        // Pair signer addresses with signatures
        address a1 = vm.addr(ownerKey1);
        address a2 = vm.addr(ownerKey2);
        address a3 = vm.addr(ownerKey3);

        bytes memory b1 = sig1;
        bytes memory b2 = sig2;
        bytes memory b3 = sig3;

        // Sort (bubble sort for 3 items), keeping address <-> signature paired
        if (a1 > a2) {
            (a1, a2) = (a2, a1);
            (b1, b2) = (b2, b1);
        }
        if (a2 > a3) {
            (a2, a3) = (a3, a2);
            (b2, b3) = (b3, b2);
        }
        if (a1 > a2) {
            (a1, a2) = (a2, a1);
            (b1, b2) = (b2, b1);
        }

        bytes[] memory sigs = new bytes[](3);
        sigs[0] = b1;
        sigs[1] = b2;
        sigs[2] = b3;

        op.signature = abi.encode(sigs);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.deal(address(account), 1e18);

        // should succeed even with 3 sigs, since contract stops at THRESHOLD=2
        entryPoint.handleOps(ops, beneficiary);

        assertEq(token.balanceOf(address(account)), token.AMOUNT());
    }

    function testUserOpFailsIfSignatureDecodingIsNotBytesArray() public {
        // signature must be abi.encode(bytes[])
        bytes memory callData = abi.encodeWithSelector(
            MultiSigAccountAbstraction.execute.selector,
            address(token),
            0,
            abi.encodeWithSelector(MockERC20.mint.selector)
        );

        PackedUserOperation memory op = _getUnsignedUserOp(callData);

        // WRONG encoding on purpose
        op.signature = abi.encodePacked(bytes32(uint256(123)));

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.deal(address(account), 1e18);
        vm.expectRevert(); // abi.decode reverts inside account.validateUserOp => bubbles to entryPoint
        entryPoint.handleOps(ops, beneficiary);
    }

    /*//////////////////////////////////////////////////////////////
                ADDITIONAL TESTS: DEPOSIT HELPERS (OPTIONAL)
    //////////////////////////////////////////////////////////////*/

    function testAddDepositIncreasesEntryPointDeposit() public {
        // your MockEntryPoint implements deposits/balanceOf in the mock
        uint256 beforeDep = account.getDeposit();

        vm.deal(owner1, 1 ether);
        vm.prank(owner1);
        account.addDeposit{ value: 0.25 ether }();

        uint256 afterDep = account.getDeposit();
        assertEq(afterDep, beforeDep + 0.25 ether);
    }
}
