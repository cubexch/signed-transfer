// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title SignedTransfer
/// @notice Handles ERC20 token transfers through signature-based actions
/// @dev Requires user's token approval on the SignedTransfer contract
contract SignedTransfer is EIP712("SignedTransfer", "1") {
    using SafeERC20 for IERC20;

    /// @notice Thrown when the recovered signer does not match the sender address
    error InvalidSigner();

    /// @notice Thrown when the inputted nonce has already been used
    error NonceUsed();

    bytes32 constant SIGNED_TRANSFER_TYPEHASH =
        keccak256("SignedTransfer(address token,address from,address to,uint256 amount,uint256 nonce)");

    /// @notice The EIP-712 domain separator
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice A map from token owner address and a caller specified word index to a bitmap. Used to set bits in the bitmap to prevent against signature replay protection
    /// @dev Uses unordered nonces so that permit messages do not need to be spent in a certain order
    /// @dev The mapping is indexed first by the token owner, then by an index specified in the nonce
    /// @dev It returns a uint256 bitmap
    /// @dev The index, or wordPosition is capped at type(uint248).max
    mapping(address => mapping(uint256 => uint256)) public nonceBitmap;

    /// @notice Transfers a token using a signed message
    /// @param token The address of the token to transfer
    /// @param from The address to transfer the token from
    /// @param to The address to transfer the token to
    /// @param amount The amount of the token to transfer
    /// @param nonce A nonce to prevent replay attacks, unique to the from address
    function signedTransfer(
        IERC20 token,
        address from,
        address to,
        uint256 amount,
        uint256 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        _useUnorderedNonce(from, nonce);

        bytes32 digest =
            _hashTypedDataV4(keccak256(abi.encode(SIGNED_TRANSFER_TYPEHASH, token, from, to, amount, nonce)));
        if (ECDSA.recover(digest, v, r, s) != from) revert InvalidSigner();

        token.safeTransferFrom(from, to, amount);
    }

    /// @notice Returns the index of the bitmap and the bit position within the bitmap. Used for unordered nonces
    /// @param nonce The nonce to get the associated word and bit positions
    /// @return wordPos The word position or index into the nonceBitmap
    /// @return bitPos The bit position
    /// @dev The first 248 bits of the nonce value is the index of the desired bitmap
    /// @dev The last 8 bits of the nonce value is the position of the bit in the bitmap
    function bitmapPositions(uint256 nonce) private pure returns (uint256 wordPos, uint256 bitPos) {
        wordPos = uint248(nonce >> 8);
        bitPos = uint8(nonce);
    }

    /// @notice Checks whether a nonce is taken and sets the bit at the bit position in the bitmap at the word position
    /// @param from The address to use the nonce at
    /// @param nonce The nonce to spend
    function _useUnorderedNonce(address from, uint256 nonce) internal {
        (uint256 wordPos, uint256 bitPos) = bitmapPositions(nonce);
        uint256 bit = 1 << bitPos;
        uint256 flipped = nonceBitmap[from][wordPos] ^= bit;

        if (flipped & bit == 0) revert NonceUsed();
    }
}
