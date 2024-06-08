// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {MockERC20} from "./mock/MockERC20.sol";
import {IERC20Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {SignedTransfer} from "../src/SignedTransfer.sol";

contract SignedTransferTest is Test {
    SignedTransfer public signedTransfer;
    bytes32 constant SIGNED_TRANSFER_TYPEHASH =
        keccak256("SignedTransfer(address token,address from,address to,uint256 amount,uint256 nonce)");
    bytes32 DOMAIN_SEPARATOR;

    MockERC20 token0;
    MockERC20 token1;

    address from;
    uint256 fromPrivateKey;

    address address2 = address(0x2);
    address address3 = address(0x3);

    function setUp() public {
        signedTransfer = new SignedTransfer();
        DOMAIN_SEPARATOR = signedTransfer.DOMAIN_SEPARATOR();

        token0 = new MockERC20("Test0", "TST0");
        token1 = new MockERC20("Test1", "TST1");

        fromPrivateKey = 0x12341234;
        from = vm.addr(fromPrivateKey);

        token0.mint(from, 10 ** 27);
        token1.mint(from, 10 ** 27);

        vm.startPrank(from);
        token0.approve(address(signedTransfer), type(uint256).max);
        token1.approve(address(signedTransfer), type(uint256).max);
        vm.stopPrank();
    }

    function testSignedTransfer() public {
        uint256 nonce = 12345;
        uint256 amount = 11 ** 18;

        uint256 startBalanceFrom = token0.balanceOf(from);
        uint256 startBalanceTo = token0.balanceOf(address2);

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(SIGNED_TRANSFER_TYPEHASH, address(token0), from, address2, amount, nonce))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fromPrivateKey, msgHash);

        signedTransfer.signedTransfer(token0, from, address2, amount, nonce, v, r, s);

        assertEq(token0.balanceOf(from), startBalanceFrom - amount);
        assertEq(token0.balanceOf(address2), startBalanceTo + amount);
    }

    function testSignedTransferInvalidSignature() public {
        uint256 nonce = 12345;
        uint256 amount = 11 ** 18;

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(SIGNED_TRANSFER_TYPEHASH, address(token0), from, address2, amount, nonce))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fromPrivateKey, msgHash);

        vm.expectRevert(SignedTransfer.InvalidSigner.selector);
        signedTransfer.signedTransfer(token0, from, address3, amount, nonce, v, r, s);

        vm.expectRevert(SignedTransfer.InvalidSigner.selector);
        signedTransfer.signedTransfer(token0, from, address2, amount + 1, nonce, v, r, s);

        vm.expectRevert(SignedTransfer.InvalidSigner.selector);
        signedTransfer.signedTransfer(token0, from, address2, amount, nonce + 1, v, r, s);

        vm.expectRevert(SignedTransfer.InvalidSigner.selector);
        signedTransfer.signedTransfer(token1, from, address2, amount, nonce, v, r, s);
    }

    function testSignedTransferDifferentDomainSeparator() public {
        uint256 nonce = 12345;
        uint256 amount = 11 ** 18;

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                keccak256("wrong"),
                keccak256(abi.encode(SIGNED_TRANSFER_TYPEHASH, address(token0), from, address2, amount, nonce))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fromPrivateKey, msgHash);

        vm.expectRevert(SignedTransfer.InvalidSigner.selector);
        signedTransfer.signedTransfer(token0, from, address2, amount, nonce, v, r, s);
    }

    function testSignedTransferNonceUsed() public {
        uint256 nonce = 12345;
        uint256 amount = 11 ** 18;

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(SIGNED_TRANSFER_TYPEHASH, address(token0), from, address2, amount, nonce))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fromPrivateKey, msgHash);

        signedTransfer.signedTransfer(token0, from, address2, amount, nonce, v, r, s);

        vm.expectRevert(SignedTransfer.NonceUsed.selector);
        signedTransfer.signedTransfer(token0, from, address2, amount, nonce, v, r, s);
    }

    function testSignedTransferNewNonce() public {
        uint256 nonce = 12345;
        uint256 amount = 11 ** 18;

        uint256 startBalanceFrom = token0.balanceOf(from);
        uint256 startBalanceTo = token0.balanceOf(address2);

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(SIGNED_TRANSFER_TYPEHASH, address(token0), from, address2, amount, nonce))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fromPrivateKey, msgHash);

        signedTransfer.signedTransfer(token0, from, address2, amount, nonce, v, r, s);

        assertEq(token0.balanceOf(from), startBalanceFrom - amount);
        assertEq(token0.balanceOf(address2), startBalanceTo + amount);

        ++nonce;
        msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(SIGNED_TRANSFER_TYPEHASH, address(token0), from, address2, amount, nonce))
            )
        );
        (v, r, s) = vm.sign(fromPrivateKey, msgHash);

        signedTransfer.signedTransfer(token0, from, address2, amount, nonce, v, r, s);

        assertEq(token0.balanceOf(from), startBalanceFrom - 2 * amount);
        assertEq(token0.balanceOf(address2), startBalanceTo + 2 * amount);
    }

    function testSignedTransferRevoked() public {
        uint256 nonce = 12345;
        uint256 amount = 11 ** 18;

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(SIGNED_TRANSFER_TYPEHASH, address(token0), from, address2, amount, nonce))
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(fromPrivateKey, msgHash);

        vm.prank(from);
        token0.approve(address(signedTransfer), 0);

        vm.expectRevert(
            abi.encodeWithSelector(IERC20Errors.ERC20InsufficientAllowance.selector, address(signedTransfer), 0, amount)
        );
        signedTransfer.signedTransfer(token0, from, address2, amount, nonce, v, r, s);
    }
}
