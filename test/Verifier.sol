// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console2} from "forge-std/Test.sol";
import {Verifer} from "../src/Verifer.sol";

contract VeriferTest is Test {
    Verifer public verifer;

    IPermit2 public permit2;

    function setUp() public {
        verifer = new Verifer();
    }

    function test_initialize() public {
        assertEq(address(verifer.permit2()), address(permit2));
    }
}
