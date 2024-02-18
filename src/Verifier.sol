// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.23;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IPermit2} from "permit2/interfaces/IPermit2.sol";
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";
import {InvalidRecipient, InvalidTransferAmount, InvalidOrderId} from "./Errors.sol";
import {SenderOrder, SenderOrderDetail, RecipientOrder, RecipientOrderDetail, Witness} from "./OrderStructs.sol";

contract Verifier is EIP712 {
    bytes32 internal constant RECIPIENT_ORDER_DETAIL_TYPEHASH =
        keccak256("RecipientOrderDetail(address to,uint256 amount,uint256 id)");

    string public constant WITNESS_TYPE_STRING =
        "Witness witness)Witness(address recipient)TokenPermissions(address token,uint256 amount)";

    IPermit2 public permit2;

    event Executed(uint256 indexed orderId);

    constructor(address _permit2) EIP712("domainBasedTramsferPrototype", "0.0.1") {
        permit2 = IPermit2(_permit2);
    }

    function execute(SenderOrder calldata _senderOrder, RecipientOrder calldata _recipientOrder) external {
        SenderOrderDetail memory senderOrderDetail = abi.decode(_senderOrder.order, (SenderOrderDetail));

        RecipientOrderDetail memory recipientOrderDetail = abi.decode(_recipientOrder.order, (RecipientOrderDetail));

        /// validation for the recipient address
        _validateRecipient(senderOrderDetail.witness, recipientOrderDetail, _recipientOrder.signature);

        /// validation for the amount
        _validateTransferAmount(senderOrderDetail.transferDetails[0].requestedAmount, recipientOrderDetail.amount);

        /// validation for the orderId
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

    function _validateRecipient(
        bytes32 _witness,
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

        Witness memory witnessData = Witness({recipient: signer});
        bytes32 witness = keccak256(abi.encode(witnessData));

        if (_witness != witness) revert InvalidRecipient();
    }

    function _validateTransferAmount(uint256 _requestedAmount, uint256 _recipientSignedAmount) private pure {
        if (_requestedAmount != _recipientSignedAmount) revert InvalidTransferAmount();
    }

    function _validateOrderId(uint256 _senderOrderId, uint256 _recipientOrderId) private pure {
        if (_senderOrderId != _recipientOrderId) revert InvalidOrderId();
    }
}
