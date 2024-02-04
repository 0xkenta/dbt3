// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.23;

import {IPermit2} from "permit2/interfaces/IPermit2.sol";
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";
import {SenderOrder, SenderOrderDetail} from "./OrderStructs.sol";

contract Verifier {
    string public constant WITNESS_TYPE_STRING =
        "Witness witness)Witness(address recipient)TokenPermissions(address token,uint256 amount)";

    IPermit2 public permit2;

    constructor(address _permit2) {
        permit2 = IPermit2(_permit2);
    }

    function execute(SenderOrder calldata _senderOrder) external {
        SenderOrderDetail memory orderDetail = abi.decode(_senderOrder.order, (SenderOrderDetail));

        permit2.permitWitnessTransferFrom(
            orderDetail.permit,
            orderDetail.transferDetails,
            orderDetail.owner,
            orderDetail.witness,
            WITNESS_TYPE_STRING,
            _senderOrder.signature
        );
    }
}
