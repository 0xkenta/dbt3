// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {IPermit2} from "permit2/interfaces/IPermit2.sol";
import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";

contract Verifier {
    IPermit2 public permit2;

    constructor(address _permit2) {
        permit2 = IPermit2(_permit2);
    }

    function execute(
        ISignatureTransfer.PermitBatchTransferFrom memory permit,
        ISignatureTransfer.SignatureTransferDetails[] calldata transferDetails,
        address owner,
        bytes32 witness,
        string calldata witnessTypeString,
        bytes calldata signature
    ) external {
        // permit2.permitWitnessTransferFrom(permit, transferDetails, owner, witness, witnessTypeString, signature);
    }
}
