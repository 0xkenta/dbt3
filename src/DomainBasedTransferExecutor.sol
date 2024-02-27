// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.23;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IPermit2} from "permit2/interfaces/IPermit2.sol";
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";
import {InvalidRecipient, InvalidTransferAmount, InvalidOrderId} from "./Errors.sol";
import {SenderOrder, SenderOrderDetail, RecipientOrder, RecipientOrderDetail, Witness} from "./OrderStructs.sol";

/// @title Domain Based Transfer
/// @author Mycel team
/// @notice This contract facilitates the transfer of ERC20 tokens based on the sender and the recipient order.
contract DomainBasedTransferExecutor is AccessControl, EIP712 {
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");

    bytes32 internal constant RECIPIENT_ORDER_DETAIL_TYPEHASH =
        keccak256("RecipientOrderDetail(address to,uint256 amount,uint256 id)");

    string public constant WITNESS_TYPE_STRING =
        "Witness witness)Witness(address recipient)TokenPermissions(address token,uint256 amount)";

    IPermit2 public permit2;

    event Executed(uint256 indexed orderId);

    constructor(address _permit2) EIP712("ID-BasedTransfer", "1") {
        permit2 = IPermit2(_permit2);

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(EXECUTOR_ROLE, msg.sender);
    }

    /// @notice This function is responsible for transferring ERC20 tokens based on the sender and the recipient order.
    /// @dev there are 3 validations for the recipient address, the transfer amount and the nonce/order id.
    /// @param _senderOrder the encoded SenderOrderDeail and the sender signature
    /// @param _recipientOrder the encoded RecipientOrderDetail and the recipient signature
    function execute(SenderOrder calldata _senderOrder, RecipientOrder calldata _recipientOrder)
        external
        onlyRole(EXECUTOR_ROLE)
    {
        SenderOrderDetail memory senderOrderDetail = abi.decode(_senderOrder.order, (SenderOrderDetail));

        RecipientOrderDetail memory recipientOrderDetail = abi.decode(_recipientOrder.order, (RecipientOrderDetail));

        /// validation for the recipient address. check whether the witness.recipient and the recipientOrder signer are the same address.
        _validateRecipient(senderOrderDetail.witness, recipientOrderDetail, _recipientOrder.signature);

        /// validation for the transfer amount. check whether the api created requestAmount and the recipient signed amount are the same.
        _validateTransferAmount(senderOrderDetail.transferDetails[0].requestedAmount, recipientOrderDetail.amount);

        /// validation for the orderId. check whether the sender order nonce and the recipient order id are the same.
        _validateOrderId(senderOrderDetail.permit.nonce, recipientOrderDetail.id);

        permit2.permitWitnessTransferFrom(
            senderOrderDetail.permit,
            senderOrderDetail.transferDetails,
            senderOrderDetail.owner,
            senderOrderDetail.witness,
            WITNESS_TYPE_STRING,
            _senderOrder.signature
        );

        emit Executed(recipientOrderDetail.id);
    }

    /// @notice recover the recipient order signer and check whether the witness recipient and the recovered signer address are the same.
    /// @dev revert if there is no match between the witness.recipient and the recipient order signer address.
    /// @param _senderOrderWitness sender order witness
    /// @param _recipientOrderDetail recipientorderDetail: the address to receive tokens, the received token amount and the order id.
    /// @param _recipientSignature the signature for the recipient order
    function _validateRecipient(
        bytes32 _senderOrderWitness,
        RecipientOrderDetail memory _recipientOrderDetail,
        bytes calldata _recipientSignature
    ) private view {
        bytes32 digest = _hashTypedDataV4(
            keccak256(
                abi.encode(
                    RECIPIENT_ORDER_DETAIL_TYPEHASH,
                    _recipientOrderDetail.to,
                    _recipientOrderDetail.amount,
                    _recipientOrderDetail.id
                )
            )
        );

        address signer = ECDSA.recover(digest, _recipientSignature);

        Witness memory witness = Witness({recipient: signer});
        bytes32 witnessWithSigner = keccak256(abi.encode(witness));

        if (_senderOrderWitness != witnessWithSigner) revert InvalidRecipient();
    }

    /// @notice verify whether the transfer amount to the recipient is correct.
    /// @dev revert if there is no match between the api created requestAmount and the recipient signed amount.
    /// @param _requestedAmount the api created requestAmount
    /// @param _recipientSignedAmount the recipient signed amount
    function _validateTransferAmount(uint256 _requestedAmount, uint256 _recipientSignedAmount) private pure {
        if (_requestedAmount != _recipientSignedAmount) revert InvalidTransferAmount();
    }

    /// @notice verify whether the sender order nonce and the recipient order id are the same.
    /// @dev revert if there is no match between the sender order nonce and the recipient order id.
    /// @param _senderOrderId the nonce of the sender order
    /// @param _recipientOrderId the id of the recipient order
    function _validateOrderId(uint256 _senderOrderId, uint256 _recipientOrderId) private pure {
        if (_senderOrderId != _recipientOrderId) revert InvalidOrderId();
    }
}
