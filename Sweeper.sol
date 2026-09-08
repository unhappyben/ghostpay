// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title StealthSweeper — EIP-7702 delegation target for sweeping stealth EOAs.
/// @dev When a stealth EOA delegates to this contract via a 7702 authorization,
///      the relayer executes one of these functions and the code runs *as the EOA*,
///      moving the EOA's own funds. The relayer pays the gas. The EOA's only onchain
///      acts ever: receive, sweep. No gas funding tx => no funding-trail leak.

interface ITornadoPool {
    function deposit(bytes32 _commitment) external payable;
}

interface IPrivacyPoolsEntrypoint {
    function deposit(uint256 _precommitment) external payable returns (uint256);
    function deposit(address _asset, uint256 _value, uint256 _precommitment) external returns (uint256);
}

interface IRailgunSmartWallet {
    // field order and sizes copied from the deployed implementation (RailgunSmartWallet /
    // Globals.sol): TokenType first, and ShieldCiphertext.encryptedBundle is bytes32[3].
    enum TokenType { ERC20, ERC721, ERC1155 }
    struct TokenData { TokenType tokenType; address tokenAddress; uint256 tokenSubID; }
    struct CommitmentPreimage { bytes32 npk; TokenData token; uint120 value; }
    struct ShieldCiphertext { bytes32[3] encryptedBundle; bytes32 shieldKey; }
    struct ShieldRequest { CommitmentPreimage preimage; ShieldCiphertext ciphertext; }
    function shield(ShieldRequest[] calldata _shieldRequests) external;
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract StealthSweeper {
    // --- mainnet constants (verify before deploy on other chains) ---
    address public constant PP_ENTRYPOINT = 0x6818809EefCe719E480a7526D76bD3e561526b46; // 0xbow Privacy Pools
    address public constant RAILGUN = 0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9;       // RailgunSmartWallet proxy

    // Tornado pools are a PURE lookup, never storage: under EIP-7702 this code executes in
    // the stealth EOA's context, and the EOA has none of this contract's storage: a
    // constructor-populated mapping would read as empty there and sweepToTornado would
    // always revert. Constants and pure code live in the bytecode, so they travel.
    // 0=0.1ETH 1=1ETH 2=10ETH 3=100ETH
    function tcPool(uint8 i) public pure returns (address) {
        if (i == 0) return 0x12D66f87A04A9E220743712cE6d9bB1B5616B8Fc; // 0.1 ETH
        if (i == 1) return 0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936; // 1 ETH
        if (i == 2) return 0x910cBd523D972eB0A6f4CaE4618AD08C15A1D7a7; // 10 ETH
        if (i == 3) return 0xA160cdAB225685dA1d56aa342Ad8841c3b53f291; // 100 ETH
        revert("bad pool");
    }

    /// Plain sweep: everything out to `to` (fresh wallet, exchange deposit, etc).
    function sweepETH(address payable to) external {
        // call, not transfer: `to` may be a smart wallet needing more than 2300 gas
        (bool ok,) = to.call{value: address(this).balance}("");
        require(ok, "ETH transfer failed");
    }

    function sweepToken(address token, address to) external {
        // full balance
        (bool ok, bytes memory d) = token.staticcall(abi.encodeWithSignature("balanceOf(address)", address(this)));
        require(ok, "balanceOf failed");
        uint256 bal = abi.decode(d, (uint256));
        require(IERC20(token).transfer(to, bal), "transfer failed");
    }

    /// Tornado Cash: deposit a fixed denomination with the user's note commitment.
    /// User generates the note offchain, withdraws later via any TC relayer/UI.
    function sweepToTornado(uint8 poolIdx, bytes32 commitment) external {
        address pool = tcPool(poolIdx);
        uint256[4] memory denoms = [uint256(0.1 ether), 1 ether, 10 ether, 100 ether];
        ITornadoPool(pool).deposit{value: denoms[poolIdx]}(commitment);
        // sweep any remainder home-free: leave it; it's a one-time address anyway
    }

    /// Privacy Pools (0xbow): arbitrary-amount deposit with a precommitment.
    /// User later proves + withdraws via the 0xbow SDK after ASP approval.
    function sweepToPrivacyPoolsETH(uint256 precommitment) external {
        IPrivacyPoolsEntrypoint(PP_ENTRYPOINT).deposit{value: address(this).balance}(precommitment);
    }

    function sweepToPrivacyPoolsToken(address asset, uint256 value, uint256 precommitment) external {
        require(IERC20(asset).approve(PP_ENTRYPOINT, value), "approve failed");
        IPrivacyPoolsEntrypoint(PP_ENTRYPOINT).deposit(asset, value, precommitment);
    }

    /// Railgun: shield ERC20 into a 0zk balance owned by the user's Railgun key.
    function sweepToRailgun(address token, uint256 value, bytes32 npk, bytes32 shieldKey, bytes32[3] memory encryptedBundle) external {
        require(IERC20(token).approve(RAILGUN, value), "approve failed");
        IRailgunSmartWallet.ShieldRequest[] memory reqs = new IRailgunSmartWallet.ShieldRequest[](1);
        reqs[0].preimage = IRailgunSmartWallet.CommitmentPreimage({
            npk: npk,
            token: IRailgunSmartWallet.TokenData({tokenType: IRailgunSmartWallet.TokenType.ERC20, tokenAddress: token, tokenSubID: 0}),
            value: uint120(value)
        });
        reqs[0].ciphertext = IRailgunSmartWallet.ShieldCiphertext({encryptedBundle: encryptedBundle, shieldKey: shieldKey});
        IRailgunSmartWallet(RAILGUN).shield(reqs);
    }
}
