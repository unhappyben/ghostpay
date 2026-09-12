// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title StealthSweeperV2 — EIP-7702 delegation target with user-signed sweep intents.
/// @dev Strict superset of Sweeper.sol: every V1 function is unchanged. V2 adds
///      executeSweep, which binds the sweep to an EIP-712 SweepIntent signed by the
///      stealth EOA itself. In V1 the user signs a 7702 authorization but the relayer
///      picks the calldata, so a malicious relayer could call sweepETH(its own address)
///      and take the whole balance. In V2 the destination, fee, deadline and action all
///      come from the signed intent, so third-party relaying is trustless.
///
///      EIP-7702 caveat (same as V1): this code executes AS the delegating stealth EOA.
///      address(this) is the EOA, storage reads/writes hit the EOA's (empty) storage,
///      and constants/pure code are the only things that travel in bytecode. That is
///      exactly what the EIP-712 domain needs: verifyingContract = address(this) pins
///      every signature to one specific stealth account, so the domain separator is
///      rebuilt fresh in memory on every call and is NEVER cached or immutable.

interface ITornadoPoolV2 {
    function deposit(bytes32 _commitment) external payable;
}

interface IPrivacyPoolsEntrypointV2 {
    function deposit(uint256 _precommitment) external payable returns (uint256);
    function deposit(address _asset, uint256 _value, uint256 _precommitment) external returns (uint256);
}

interface IRailgunSmartWalletV2 {
    // field order and sizes copied from the deployed implementation (RailgunSmartWallet /
    // Globals.sol): TokenType first, and ShieldCiphertext.encryptedBundle is bytes32[3].
    enum TokenType { ERC20, ERC721, ERC1155 }
    struct TokenData { TokenType tokenType; address tokenAddress; uint256 tokenSubID; }
    struct CommitmentPreimage { bytes32 npk; TokenData token; uint120 value; }
    struct ShieldCiphertext { bytes32[3] encryptedBundle; bytes32 shieldKey; }
    struct ShieldRequest { CommitmentPreimage preimage; ShieldCiphertext ciphertext; }
    function shield(ShieldRequest[] calldata _shieldRequests) external;
}

interface IERC20V2 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract StealthSweeperV2 {
    // --- mainnet constants (verify before deploy on other chains) ---
    address public constant PP_ENTRYPOINT = 0x6818809EefCe719E480a7526D76bD3e561526b46; // 0xbow Privacy Pools
    address public constant RAILGUN = 0xFA7093CDD9EE6932B4eb2c9e1cde7CE00B1FA4b9;       // RailgunSmartWallet proxy

    // --- EIP-712 ---
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant SWEEP_INTENT_TYPEHASH =
        keccak256("SweepIntent(uint8 action,address token,address destination,uint256 precommitment,uint256 feeBps,uint256 deadline)");
    bytes32 private constant NAME_HASH = keccak256(bytes("GhostpaySweeper"));
    bytes32 private constant VERSION_HASH = keccak256(bytes("1"));

    // hard cap on the relayer fee, enforced against the signed intent (10%)
    uint256 public constant MAX_FEE_BPS = 1000;

    struct SweepIntent {
        uint8 action;          // 0 = ETH to destination, 1 = PP ETH deposit, 2 = PP token deposit, 3 = token to destination
        address token;         // actions 2/3 only (ignored otherwise)
        address destination;   // actions 0/3 only (ignored otherwise)
        uint256 precommitment; // actions 1/2 only (ignored otherwise)
        uint256 feeBps;        // relayer fee in basis points of the swept amount, paid to tx.origin
        uint256 deadline;      // intent valid while block.timestamp <= deadline
    }

    /// Domain separator, rebuilt fresh on every call. Under 7702 address(this) is the
    /// delegating stealth EOA, so this binds each signature to exactly one stealth
    /// account. Never cache this in storage or an immutable: neither survives 7702.
    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    /// The exact digest the stealth key signs. Exposed so the frontend and tests build
    /// the same bytes as the onchain check.
    function hashSweepIntent(SweepIntent calldata intent) public view returns (bytes32) {
        return keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparator(),
            keccak256(abi.encode(
                SWEEP_INTENT_TYPEHASH,
                intent.action,
                intent.token,
                intent.destination,
                intent.precommitment,
                intent.feeBps,
                intent.deadline
            ))
        ));
    }

    /// Execute a user-signed sweep intent. The relayer supplies intent + signature;
    /// every parameter of the sweep is bound by the signature, so the relayer can only
    /// deliver, never redirect.
    function executeSweep(SweepIntent calldata intent, bytes calldata sig) external {
        require(block.timestamp <= intent.deadline, "intent expired");
        require(intent.feeBps <= MAX_FEE_BPS, "fee too high");
        // the stealth key signed over a domain whose verifyingContract is address(this),
        // so a valid recovery can only ever equal the executing account
        require(_recoverSigner(hashSweepIntent(intent), sig) == address(this), "signer is not this account");

        if (intent.action == 0) {
            // plain ETH sweep: full balance minus fee to destination
            uint256 fee = address(this).balance * intent.feeBps / 10000;
            (bool ok,) = intent.destination.call{value: address(this).balance - fee}("");
            require(ok, "ETH transfer failed");
            _payFeeETH(fee);
        } else if (intent.action == 1) {
            // Privacy Pools ETH deposit of (balance minus fee) with precommitment
            uint256 fee = address(this).balance * intent.feeBps / 10000;
            IPrivacyPoolsEntrypointV2(PP_ENTRYPOINT).deposit{value: address(this).balance - fee}(intent.precommitment);
            _payFeeETH(fee);
        } else if (intent.action == 2) {
            // Privacy Pools token deposit: full token balance minus fee, with precommitment
            uint256 bal = _tokenBalance(intent.token);
            uint256 fee = bal * intent.feeBps / 10000;
            uint256 amount = bal - fee;
            require(IERC20V2(intent.token).approve(PP_ENTRYPOINT, amount), "approve failed");
            IPrivacyPoolsEntrypointV2(PP_ENTRYPOINT).deposit(intent.token, amount, intent.precommitment);
            _payFeeToken(intent.token, fee);
        } else if (intent.action == 3) {
            // plain token sweep: full balance minus fee to destination
            uint256 bal = _tokenBalance(intent.token);
            uint256 fee = bal * intent.feeBps / 10000;
            require(IERC20V2(intent.token).transfer(intent.destination, bal - fee), "transfer failed");
            _payFeeToken(intent.token, fee);
        } else {
            revert("bad action");
        }
    }

    /// OpenZeppelin-style ECDSA recovery, inlined to keep this file import-free like V1.
    function _recoverSigner(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 0x20))
            v := byte(0, calldataload(add(sig.offset, 0x40)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "bad sig v");
        // malleability check: s must be in the lower half of the secp256k1 order
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "bad sig s");
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "bad sig");
        return signer;
    }

    function _tokenBalance(address token) internal view returns (uint256) {
        (bool ok, bytes memory d) = token.staticcall(abi.encodeWithSignature("balanceOf(address)", address(this)));
        require(ok, "balanceOf failed");
        return abi.decode(d, (uint256));
    }

    /// Fee goes to tx.origin, NOT msg.sender: in batched relaying msg.sender is the
    /// BatchRelayer dispatcher contract, while tx.origin is always the relayer runner
    /// EOA that actually paid the gas.
    function _payFeeETH(uint256 fee) internal {
        if (fee == 0) return;
        (bool ok,) = tx.origin.call{value: fee}("");
        require(ok, "fee transfer failed");
    }

    function _payFeeToken(address token, uint256 fee) internal {
        if (fee == 0) return;
        require(IERC20V2(token).transfer(tx.origin, fee), "fee transfer failed");
    }

    // ------------------------------------------------------------------------
    // V1 surface, unchanged from Sweeper.sol
    // ------------------------------------------------------------------------

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
        require(IERC20V2(token).transfer(to, bal), "transfer failed");
    }

    /// Tornado Cash: deposit a fixed denomination with the user's note commitment.
    /// User generates the note offchain, withdraws later via any TC relayer/UI.
    function sweepToTornado(uint8 poolIdx, bytes32 commitment) external {
        address pool = tcPool(poolIdx);
        uint256[4] memory denoms = [uint256(0.1 ether), 1 ether, 10 ether, 100 ether];
        ITornadoPoolV2(pool).deposit{value: denoms[poolIdx]}(commitment);
        // sweep any remainder home-free: leave it; it's a one-time address anyway
    }

    /// Privacy Pools (0xbow): arbitrary-amount deposit with a precommitment.
    /// User later proves + withdraws via the 0xbow SDK after ASP approval.
    function sweepToPrivacyPoolsETH(uint256 precommitment) external {
        IPrivacyPoolsEntrypointV2(PP_ENTRYPOINT).deposit{value: address(this).balance}(precommitment);
    }

    function sweepToPrivacyPoolsToken(address asset, uint256 value, uint256 precommitment) external {
        require(IERC20V2(asset).approve(PP_ENTRYPOINT, value), "approve failed");
        IPrivacyPoolsEntrypointV2(PP_ENTRYPOINT).deposit(asset, value, precommitment);
    }

    /// Railgun: shield ERC20 into a 0zk balance owned by the user's Railgun key.
    function sweepToRailgun(address token, uint256 value, bytes32 npk, bytes32 shieldKey, bytes32[3] memory encryptedBundle) external {
        require(IERC20V2(token).approve(RAILGUN, value), "approve failed");
        IRailgunSmartWalletV2.ShieldRequest[] memory reqs = new IRailgunSmartWalletV2.ShieldRequest[](1);
        reqs[0].preimage = IRailgunSmartWalletV2.CommitmentPreimage({
            npk: npk,
            token: IRailgunSmartWalletV2.TokenData({tokenType: IRailgunSmartWalletV2.TokenType.ERC20, tokenAddress: token, tokenSubID: 0}),
            value: uint120(value)
        });
        reqs[0].ciphertext = IRailgunSmartWalletV2.ShieldCiphertext({encryptedBundle: encryptedBundle, shieldKey: shieldKey});
        IRailgunSmartWalletV2(RAILGUN).shield(reqs);
    }
}
