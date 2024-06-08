// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {SignedTransfer} from "src/SignedTransfer.sol";

bytes32 constant SALT = keccak256(unicode"🧊");

contract DeploySignedTransfer is Script {
    function setUp() public {}

    function run() public returns (SignedTransfer signedTransfer) {
        vm.broadcast();
        signedTransfer = new SignedTransfer{salt: SALT}();
    }
}
