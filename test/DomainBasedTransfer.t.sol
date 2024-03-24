// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import {IPermit2} from "permit2/interfaces/IPermit2.sol";
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";
import {SignatureVerification} from "permit2/libraries/SignatureVerification.sol";
import {MockERC20} from "./mock/MockERC20.sol";
import {AddressBuilder} from "./utils/AddressBuilder.sol";
import {PermitSignature} from "./utils/PermitSignature.sol";
import {StructBuilder} from "./utils/StructBuilder.sol";
import {DomainBasedTransferExecutor} from "../src/DomainBasedTransferExecutor.sol";
import {SenderOrder, SenderOrderDetail, RecipientOrder, RecipientOrderDetail} from "../src/OrderStructs.sol";
import {InvalidRecipient, InvalidTransferAmount, InvalidOrderId} from "../src/Errors.sol";

error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);
error InvalidNonce();
error SignatureExpired(uint256 signatureDeadline);

contract MockExecutor is DomainBasedTransferExecutor {
    constructor(address _permit2) DomainBasedTransferExecutor(_permit2) {}

    function structHash(RecipientOrderDetail calldata _recipientOrderDetail) external view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    RECIPIENT_ORDER_DETAIL_TYPEHASH,
                    _recipientOrderDetail.to,
                    _recipientOrderDetail.amount,
                    _recipientOrderDetail.id
                )
            )
        );
    }
}

contract DomainBaseTransferExecutorTest is Test, PermitSignature {
    using AddressBuilder for address[];

    struct Witness {
        address recipient;
    }

    struct InvalidWitness {
        uint256 amount;
    }

    string public constant PERMIT_BATCH_WITNESS_TRANSFER_TYPEHASH_STUB =
        "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,";

    bytes32 constant WITNESS_BATCH_TYPEHASH = keccak256(
        "PermitBatchWitnessTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline,Witness witness)Witness(address recipient)TokenPermissions(address token,uint256 amount)"
    );

    MockExecutor public executor;
    MockERC20 public token1;
    MockERC20 public token2;

    uint256 public constant DEFAULT_AMOUNT = 1 ether;
    uint256 public constant DEFAULT_BALANCE = 2 ether;
    bytes32 DOMAIN_SEPARATOR;

    address public permit2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    address public sender;
    uint256 public senderPrivateKey;

    address public defaultDefinedAddress;

    address public recipient;
    uint256 public recipientPrivateKey;

    address public other;
    uint256 public otherPrivateKey;

    address toAddress = address(0x1);
    address feeReceiver = address(0x2);

    uint256 public deadline;

    event Executed(uint256 indexed orderId);

    function setUp() public {
        executor = new MockExecutor(permit2);
        token1 = new MockERC20("token1", "TOKEN1");
        token2 = new MockERC20("token2", "TOKEN2");

        DOMAIN_SEPARATOR = executor.permit2().DOMAIN_SEPARATOR();

        senderPrivateKey = 0x12341234;
        sender = vm.addr(senderPrivateKey);

        defaultDefinedAddress = vm.addr(1);

        recipientPrivateKey = 0x12345678;
        recipient = vm.addr(recipientPrivateKey);

        otherPrivateKey = 0x12345679;
        other = vm.addr(otherPrivateKey);

        token1.mint(sender, DEFAULT_BALANCE);
        token2.mint(sender, DEFAULT_BALANCE);

        vm.startPrank(sender);
        token1.approve(permit2, type(uint256).max);
        token2.approve(permit2, type(uint256).max);
        vm.stopPrank();

        deadline = block.timestamp + 100;
    }

    function test_initialize() public {
        assertEq(address(executor.permit2()), permit2);
        assertEq(token1.balanceOf(sender), DEFAULT_BALANCE);
        assertEq(token2.balanceOf(sender), DEFAULT_BALANCE);
        assertTrue(executor.hasRole(executor.DEFAULT_ADMIN_ROLE(), address(this)));
        assertTrue(executor.hasRole(executor.EXECUTOR_ROLE(), address(this)));
    }

    function test_witnessTypeHashes() public {
        assertEq(
            keccak256(abi.encodePacked(PERMIT_BATCH_WITNESS_TRANSFER_TYPEHASH_STUB, executor.WITNESS_TYPE_STRING())),
            WITNESS_BATCH_TYPEHASH
        );
    }

    function test_execute_with_default_address_revert_if_caller_has_no_executor_role() public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, defaultDefinedAddress).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);

        vm.expectRevert(
            abi.encodeWithSelector(AccessControlUnauthorizedAccount.selector, other, executor.EXECUTOR_ROLE())
        );
        vm.prank(other);
        executor.execute(senderOrder);
    }

    function test_execute_with_default_address_transfer_to_default_defined_address() public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, defaultDefinedAddress).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);

        uint256 senderToken1Before = token1.balanceOf(sender);
        uint256 recipientToken1Before = token1.balanceOf(recipient);
        uint256 defaultAddressToken1Before = token1.balanceOf(defaultDefinedAddress);
        uint256 feeReceiverToken1Before = token1.balanceOf(feeReceiver);
        assertEq(recipientToken1Before, 0);
        assertEq(defaultAddressToken1Before, 0);
        assertEq(feeReceiverToken1Before, 0);

        executor.execute(senderOrder);

        uint256 senderToken1After = token1.balanceOf(sender);
        uint256 recipientToken1After = token1.balanceOf(recipient);
        uint256 defaultAddressToken1After = token1.balanceOf(defaultDefinedAddress);
        uint256 feeReceiverToken1After = token1.balanceOf(feeReceiver);
        assertEq(senderToken1After, senderToken1Before - DEFAULT_AMOUNT * 2);
        assertEq(recipientToken1After, recipientToken1Before);
        assertEq(defaultAddressToken1After, defaultAddressToken1Before + DEFAULT_AMOUNT);
        assertEq(feeReceiverToken1After, feeReceiverToken1Before + DEFAULT_AMOUNT);
    }

    function test_execute_with_default_address_emit_Executed_event() public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, defaultDefinedAddress).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);

        vm.expectEmit(true, false, false, true);
        emit Executed(nonce);
        executor.execute(senderOrder);
    }

    function test_execute_transfer_to_recipient_adddress() public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, address(recipient)).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);
        RecipientOrder memory recipientOrder = _getRecipientOrder(recipient, DEFAULT_AMOUNT, nonce, recipientPrivateKey);

        uint256 senderToken1Before = token1.balanceOf(sender);
        uint256 recipientToken1Before = token1.balanceOf(recipient);
        uint256 feeReceiverToken1Before = token1.balanceOf(feeReceiver);
        assertEq(recipientToken1Before, 0);
        assertEq(feeReceiverToken1Before, 0);

        executor.execute(senderOrder, recipientOrder);

        uint256 senderToken1After = token1.balanceOf(sender);
        uint256 recipientToken1After = token1.balanceOf(recipient);
        uint256 feeReceiverToken1After = token1.balanceOf(feeReceiver);
        assertEq(senderToken1After, senderToken1Before - DEFAULT_AMOUNT * 2);
        assertEq(recipientToken1After, recipientToken1Before + DEFAULT_AMOUNT);
        assertEq(feeReceiverToken1After, feeReceiverToken1Before + DEFAULT_AMOUNT);
    }

    function test_execute_transfer_to_recipient_wished_adddress() public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, address(toAddress)).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);
        RecipientOrder memory recipientOrder = _getRecipientOrder(recipient, DEFAULT_AMOUNT, nonce, recipientPrivateKey);

        uint256 senderToken1Before = token1.balanceOf(sender);
        uint256 recipientToken1Before = token1.balanceOf(recipient);
        uint256 toAdressToken1Before = token1.balanceOf(toAddress);
        uint256 feeReceiverToken1Before = token1.balanceOf(feeReceiver);
        assertEq(recipientToken1Before, 0);
        assertEq(toAdressToken1Before, 0);
        assertEq(feeReceiverToken1Before, 0);

        executor.execute(senderOrder, recipientOrder);

        uint256 senderToken1After = token1.balanceOf(sender);
        uint256 recipientToken1After = token1.balanceOf(recipient);
        uint256 toAddressToken1After = token1.balanceOf(toAddress);
        uint256 feeReceiverToken1After = token1.balanceOf(feeReceiver);
        assertEq(senderToken1After, senderToken1Before - DEFAULT_AMOUNT * 2);
        assertEq(recipientToken1After, recipientToken1Before);
        assertEq(toAddressToken1After, toAdressToken1Before + DEFAULT_AMOUNT);
        assertEq(feeReceiverToken1After, feeReceiverToken1Before + DEFAULT_AMOUNT);
    }

    function test_execute_emit_Executed_event() public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, address(recipient)).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);
        RecipientOrder memory recipientOrder = _getRecipientOrder(recipient, DEFAULT_AMOUNT, nonce, recipientPrivateKey);

        vm.expectEmit(true, false, false, true);
        emit Executed(nonce);
        executor.execute(senderOrder, recipientOrder);
    }

    function test_execute_revert_if_caller_has_no_executor_role() public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, address(recipient)).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);
        RecipientOrder memory recipientOrder = _getRecipientOrder(recipient, DEFAULT_AMOUNT, nonce, recipientPrivateKey);

        vm.expectRevert(
            abi.encodeWithSelector(AccessControlUnauthorizedAccount.selector, other, executor.EXECUTOR_ROLE())
        );
        vm.prank(other);
        executor.execute(senderOrder, recipientOrder);
    }

    /// tests for the validation: _validateRecipient
    function test_execute_with_random_recipients(uint256 _privateKey) public {
        vm.assume(_privateKey != 0);
        vm.assume(_privateKey < 10000);
        address randomRecipient = vm.addr(_privateKey);

        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(randomRecipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, address(randomRecipient)).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);
        RecipientOrder memory recipientOrder = _getRecipientOrder(randomRecipient, DEFAULT_AMOUNT, nonce, _privateKey);

        uint256 senderToken1Before = token1.balanceOf(sender);
        uint256 recipientToken1Before = token1.balanceOf(randomRecipient);
        uint256 feeReceiverToken1Before = token1.balanceOf(feeReceiver);
        assertEq(recipientToken1Before, 0);
        assertEq(feeReceiverToken1Before, 0);

        executor.execute(senderOrder, recipientOrder);

        uint256 senderToken1After = token1.balanceOf(sender);
        uint256 recipientToken1After = token1.balanceOf(randomRecipient);
        uint256 feeReceiverToken1After = token1.balanceOf(feeReceiver);
        assertEq(senderToken1After, senderToken1Before - DEFAULT_AMOUNT * 2);
        assertEq(recipientToken1After, recipientToken1Before + DEFAULT_AMOUNT);
        assertEq(feeReceiverToken1After, feeReceiverToken1Before + DEFAULT_AMOUNT);
    }

    function test_execute_revert_if_no_match_between_witness_recipient_and_recipientOrder_signer() public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, address(recipient)).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);
        RecipientOrder memory recipientOrder = _getRecipientOrder(recipient, DEFAULT_AMOUNT, nonce, otherPrivateKey);

        vm.expectRevert(InvalidRecipient.selector);
        executor.execute(senderOrder, recipientOrder);
    }

    function test_execute_revert_if_willness_is_invalid() public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, address(recipient)).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        InvalidWitness memory wrongData = InvalidWitness({amount: 1 ether});
        bytes32 invalidWitness = keccak256(abi.encode(wrongData));
        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, invalidWitness, sig);
        RecipientOrder memory recipientOrder = _getRecipientOrder(recipient, DEFAULT_AMOUNT, nonce, recipientPrivateKey);

        vm.expectRevert(InvalidRecipient.selector);
        executor.execute(senderOrder, recipientOrder);
    }

    /// tests for the validation: _validateTransferAmount
    function test_execute_transfer_random_amount(uint256 _amount) public {
        vm.assume(_amount < DEFAULT_AMOUNT);
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, address(recipient)).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(_amount, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);
        RecipientOrder memory recipientOrder = _getRecipientOrder(recipient, _amount, nonce, recipientPrivateKey);

        uint256 senderToken1Before = token1.balanceOf(sender);
        uint256 recipientToken1Before = token1.balanceOf(recipient);
        uint256 feeReceiverToken1Before = token1.balanceOf(feeReceiver);
        assertEq(recipientToken1Before, 0);
        assertEq(feeReceiverToken1Before, 0);

        executor.execute(senderOrder, recipientOrder);

        uint256 senderToken1After = token1.balanceOf(sender);
        uint256 recipientToken1After = token1.balanceOf(recipient);
        uint256 feeReceiverToken1After = token1.balanceOf(feeReceiver);
        assertEq(senderToken1After, senderToken1Before - (_amount + DEFAULT_AMOUNT));
        assertEq(recipientToken1After, recipientToken1Before + _amount);
        assertEq(feeReceiverToken1After, feeReceiverToken1Before + DEFAULT_AMOUNT);
    }

    function test_execute_revert_if_no_match_transferDetailsRequestedAmount_and_recipientOrderAmount() public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, address(recipient)).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);
        RecipientOrder memory recipientOrder =
            _getRecipientOrder(recipient, DEFAULT_AMOUNT - 1, nonce, recipientPrivateKey);

        vm.expectRevert(InvalidTransferAmount.selector);
        executor.execute(senderOrder, recipientOrder);
    }

    /// tests for the validation: _validateTransferAmount
    function test_execute_transfer_with_random_nonce(uint256 _timestamp) public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, _timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, address(recipient)).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);
        RecipientOrder memory recipientOrder = _getRecipientOrder(recipient, DEFAULT_AMOUNT, nonce, recipientPrivateKey);

        uint256 senderToken1Before = token1.balanceOf(sender);
        uint256 recipientToken1Before = token1.balanceOf(recipient);
        uint256 feeReceiverToken1Before = token1.balanceOf(feeReceiver);
        assertEq(recipientToken1Before, 0);
        assertEq(feeReceiverToken1Before, 0);

        executor.execute(senderOrder, recipientOrder);

        uint256 senderToken1After = token1.balanceOf(sender);
        uint256 recipientToken1After = token1.balanceOf(recipient);
        uint256 feeReceiverToken1After = token1.balanceOf(feeReceiver);
        assertEq(senderToken1After, senderToken1Before - DEFAULT_AMOUNT * 2);
        assertEq(recipientToken1After, recipientToken1Before + DEFAULT_AMOUNT);
        assertEq(feeReceiverToken1After, feeReceiverToken1Before + DEFAULT_AMOUNT);
    }

    function test_execute_revert_if_no_match_between_nonce_and_recipientOrderId() public {
        uint256 timestamp = block.timestamp;
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, timestamp)));

        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, address(recipient)).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        uint256 invalidOrderId = nonce + 1;
        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);
        RecipientOrder memory recipientOrder =
            _getRecipientOrder(recipient, DEFAULT_AMOUNT, invalidOrderId, recipientPrivateKey);

        vm.expectRevert(InvalidOrderId.selector);
        executor.execute(senderOrder, recipientOrder);
    }

    /// tests related to the permit2
    function test_execute_revert_if_invalid_sender_signature_length_given() public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        bytes memory sigExtra = bytes.concat(sig, bytes1(uint8(0)));
        assertEq(sigExtra.length, 66);

        address[] memory to = AddressBuilder.fill(1, address(recipient)).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sigExtra);
        RecipientOrder memory recipientOrder = _getRecipientOrder(recipient, DEFAULT_AMOUNT, nonce, recipientPrivateKey);

        vm.expectRevert(SignatureVerification.InvalidSignatureLength.selector);
        executor.execute(senderOrder, recipientOrder);
    }

    function test_execute_revert_if_permit_deadline_is_over() public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, address(recipient)).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);
        RecipientOrder memory recipientOrder = _getRecipientOrder(recipient, DEFAULT_AMOUNT, nonce, recipientPrivateKey);

        skip(deadline - block.timestamp + 1);
        vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, deadline));
        executor.execute(senderOrder, recipientOrder);
    }

    function test_execute_revert_if_used_nonce_given() public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, address(recipient)).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);
        RecipientOrder memory recipientOrder = _getRecipientOrder(recipient, DEFAULT_AMOUNT, nonce, recipientPrivateKey);

        executor.execute(senderOrder, recipientOrder);

        vm.expectRevert(InvalidNonce.selector);
        executor.execute(senderOrder, recipientOrder);
    }

    function test_execute_revert_if_no_match_between_PermitBatchTransferform_and_transferDetails_length() public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, WITNESS_BATCH_TYPEHASH, witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, address(recipient));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);
        RecipientOrder memory recipientOrder = _getRecipientOrder(recipient, DEFAULT_AMOUNT, nonce, recipientPrivateKey);

        vm.expectRevert(ISignatureTransfer.LengthMismatch.selector);
        executor.execute(senderOrder, recipientOrder);
    }

    function test_execute_revert_if__typeHash_is_invalid() public {
        uint256 nonce = uint256(keccak256(abi.encodePacked(address(executor), sender, block.timestamp)));
        Witness memory witnessData = Witness(recipient);
        bytes32 witness = keccak256(abi.encode(witnessData));
        address[] memory tokens = AddressBuilder.fill(1, address(token1)).push(address(token1));
        ISignatureTransfer.PermitBatchTransferFrom memory permit =
            getPermitTransferFrom(tokens, nonce, DEFAULT_AMOUNT, deadline);

        bytes memory sig = getPermitBatchWitnessSignature(
            permit, senderPrivateKey, "invalid typedHash", witness, DOMAIN_SEPARATOR, address(executor)
        );

        address[] memory to = AddressBuilder.fill(1, address(recipient)).push(address(feeReceiver));
        ISignatureTransfer.SignatureTransferDetails[] memory toAmountPairs =
            StructBuilder.fillSigTransferDetails(DEFAULT_AMOUNT, DEFAULT_AMOUNT, to);

        SenderOrder memory senderOrder = _getSenderOrder(permit, toAmountPairs, sender, witness, sig);
        RecipientOrder memory recipientOrder = _getRecipientOrder(recipient, DEFAULT_AMOUNT, nonce, recipientPrivateKey);

        vm.expectRevert(SignatureVerification.InvalidSigner.selector);
        executor.execute(senderOrder, recipientOrder);
    }

    function test_grant_role_to_other_by_DEFAULT_ADMIN_ROLE() public {
        assertTrue(!executor.hasRole(executor.EXECUTOR_ROLE(), other));

        executor.grantRole(executor.EXECUTOR_ROLE(), other);

        assertTrue(executor.hasRole(executor.EXECUTOR_ROLE(), other));
    }

    function _getSenderOrder(
        ISignatureTransfer.PermitBatchTransferFrom memory _permit,
        ISignatureTransfer.SignatureTransferDetails[] memory _toAmountPairs,
        address _owner,
        bytes32 _witness,
        bytes memory _signature
    ) private pure returns (SenderOrder memory) {
        SenderOrder memory senderOrder =
            SenderOrder(abi.encode(SenderOrderDetail(_permit, _toAmountPairs, _owner, _witness)), _signature);

        return senderOrder;
    }

    function _getRecipientOrder(address _to, uint256 _amount, uint256 _id, uint256 _recipientPrivateKey)
        private
        view
        returns (RecipientOrder memory)
    {
        RecipientOrderDetail memory recipientOrderDetail = RecipientOrderDetail({to: _to, amount: _amount, id: _id});

        bytes32 digest = executor.structHash(recipientOrderDetail);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_recipientPrivateKey, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory order = abi.encode(recipientOrderDetail);

        return RecipientOrder({order: order, signature: signature});
    }
}
