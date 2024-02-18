pragma solidity 0.8.23;

import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";

struct SenderOrder {
    bytes order;
    bytes signature;
}

struct SenderOrderDetail {
    ISignatureTransfer.PermitBatchTransferFrom permit;
    ISignatureTransfer.SignatureTransferDetails[] transferDetails;
    address owner;
    bytes32 witness;
}

struct RecipientOrder {
    bytes order;
    bytes signature;
}

struct RecipientOrderDetail {
    address to;
    uint256 amount;
    uint256 id;
}

struct Witness {
    address recipient;
}
