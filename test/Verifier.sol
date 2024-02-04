// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {Verifier} from "../src/Verifier.sol";
import {IPermit2} from "permit2/interfaces/IPermit2.sol";

contract VeriferTest is Test {
    Verifier public verifier;

    address public permit2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    uint256 public DEFAULT_FEE_AMOUNT = 1 ether;

    function setUp() public {
        verifier = new Verifier(permit2);
    }

    function test_initialize() public {
        assertEq(address(verifier.permit2()), permit2);
    }

    function test_execute() public {
        uint256 nonce = 0;
    }
}
