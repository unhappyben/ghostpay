// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title PayAndAnnounce: ERC-5564 stealth payment and announcement in one transaction.
/// @dev Today a stealth payment is two steps: the sender transfers ETH/tokens to the
///      stealth address, then a separate announcement is submitted (relayer POST
///      /announce, or an EIP-5792 batch in supporting wallets). This contract folds
///      both into a single call: it emits the ERC-5564 Announcement event via the
///      canonical singleton AND forwards the payment, atomically. If the payment
///      cannot be delivered the whole transaction reverts, so no announcement is
///      ever left pointing at a payment that did not happen.
///
///      The contract emits nothing of its own: the Announcement event from the
///      singleton is the entire output, identical in shape to what the relayer or
///      a 5792 batch produces today. Wallets and indexers see no difference.
///
///      Token payments: payToken pulls via transferFrom, so the sender must approve
///      this contract for `amount` first (a separate prior transaction, or an
///      EIP-5792 batch of approve + payToken in one user confirmation).

interface IERC5564Announcer {
    function announce(uint256 schemeId, address stealthAddress, bytes calldata ephemeralPubKey, bytes calldata metadata) external;
}

interface IERC20PA {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract PayAndAnnounce {
    // --- mainnet constants (verify before deploy on other chains) ---
    address public constant ANNOUNCER = 0x55649E01B5Df198D18D95b5cc5051630cfD45564; // ERC-5564 singleton
    uint256 public constant SCHEME_ID = 1; // secp256k1 with view tags, same as the relayer path

    /// Pay a stealth address in ETH and announce it in one call. The announcement
    /// goes first; if the value transfer fails the whole call reverts and the
    /// announcement is rolled back with it. `call`, not `transfer`: the stealth
    /// address may be a smart wallet needing more than 2300 gas.
    function pay(address payable stealth, bytes calldata ephPub, bytes calldata metadata) external payable {
        IERC5564Announcer(ANNOUNCER).announce(SCHEME_ID, stealth, ephPub, metadata);
        (bool ok,) = stealth.call{value: msg.value}("");
        require(ok, "ETH transfer failed");
    }

    /// Pay a stealth address in an ERC-20 and announce it in one call. Requires a
    /// prior approve of this contract for at least `amount` (or a 5792 batch of
    /// approve + payToken). Same atomicity rule: a failed transferFrom rolls back
    /// the announcement too.
    function payToken(address token, address stealth, uint256 amount, bytes calldata ephPub, bytes calldata metadata) external {
        IERC5564Announcer(ANNOUNCER).announce(SCHEME_ID, stealth, ephPub, metadata);
        require(IERC20PA(token).transferFrom(msg.sender, stealth, amount), "transferFrom failed");
    }
}
