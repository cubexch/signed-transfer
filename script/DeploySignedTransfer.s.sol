// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {SignedTransfer} from "src/SignedTransfer.sol";

address constant CREATEX_ADDRESS = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;
bytes32 constant CREATEX_CODEHASH = 0xbd8a7ea8cfca7b4e5f5041d7d4b17bc317c5ce42cfbc42066a00cf26b43eb53f;

interface ICreateX {
    function deployCreate2(bytes32 salt, bytes memory initCode) external payable returns (address newContract);
}

bytes32 constant SALT = 0x671d94f5c71d4234178a8fd82c9b53f7d770ade6d0d520293c23cea1588ac5b4;

contract DeploySignedTransfer is Script {
    ICreateX constant createX = ICreateX(CREATEX_ADDRESS);

    function setUp() public view {
        require(address(createX).codehash == CREATEX_CODEHASH, "CreateX not deployed");
    }

    function run() public returns (SignedTransfer signedTransfer) {
        vm.broadcast();
        signedTransfer = SignedTransfer(createX.deployCreate2(SALT, type(SignedTransfer).creationCode));
    }
}
