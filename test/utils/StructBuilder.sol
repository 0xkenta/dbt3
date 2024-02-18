pragma solidity 0.8.23;

import {ISignatureTransfer} from "permit2/interfaces/ISignatureTransfer.sol";

library StructBuilder {
    function fillSigTransferDetails(uint256 amount, uint256 feeAmount, address[] memory tos)
        public
        pure
        returns (ISignatureTransfer.SignatureTransferDetails[] memory transferDetails)
    {
        transferDetails = new ISignatureTransfer.SignatureTransferDetails[](tos.length);
        for (uint256 i = 0; i < tos.length; ++i) {
            uint256 requestedAmount = i == 0 ? amount : feeAmount;
            transferDetails[i] =
                ISignatureTransfer.SignatureTransferDetails({to: tos[i], requestedAmount: requestedAmount});
        }
    }
}
