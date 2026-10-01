// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../SweeperV2.sol";

interface IPPEntrypointConfigUsdc {
    function assetConfig(address asset) external view returns (address pool, uint256 minimumDepositAmount, uint256 vettingFeeBps);
}

interface IUsdcLike {
    function balanceOf(address account) external view returns (uint256);
}

/// Fork-only. Intent action 2 (Privacy Pools token deposit) against the real mainnet
/// USDC pool, delegating to the DEPLOYED SweeperV2 bytecode the relayer uses in
/// production, plus a freshly compiled copy to prove source and deployment agree.
/// Nothing is ever broadcast.
contract SweeperV2UsdcPoolTest is Test {
    address constant PP_ENTRYPOINT = 0x6818809EefCe719E480a7526D76bD3e561526b46;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant USDC_POOL = 0xb419c2867aB3CBc78921660cB95150d95A94ce86;
    address constant DEPLOYED_SWEEPER_V2 = 0xCC29c7723116155ccF20C7c0b8924F4747331903;
    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    bytes32 constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant SWEEP_INTENT_TYPEHASH =
        keccak256("SweepIntent(uint8 action,address token,address destination,uint256 precommitment,uint256 feeBps,uint256 deadline)");

    function setUp() public {
        vm.createSelectFork(vm.envOr("MAINNET_RPC", string("https://eth.drpc.org")));
    }

    function _sign(uint256 pk, StealthSweeperV2.SweepIntent memory intent, address account) internal view returns (bytes memory) {
        bytes32 domain = keccak256(abi.encode(
            DOMAIN_TYPEHASH, keccak256(bytes("GhostpaySweeper")), keccak256(bytes("1")), block.chainid, account
        ));
        bytes32 structHash = keccak256(abi.encode(
            SWEEP_INTENT_TYPEHASH,
            intent.action, intent.token, intent.destination, intent.precommitment, intent.feeBps, intent.deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, keccak256(abi.encodePacked("\x19\x01", domain, structHash)));
        return abi.encodePacked(r, s, v);
    }

    function _intent(Vm.Wallet memory stealth, uint256 feeBps, string memory label)
        internal view returns (StealthSweeperV2.SweepIntent memory intent, bytes memory sig)
    {
        intent = StealthSweeperV2.SweepIntent({
            action: 2,
            token: USDC,
            destination: address(0),
            precommitment: uint256(keccak256(bytes(label))) % SNARK_SCALAR_FIELD,
            feeBps: feeBps,
            deadline: block.timestamp + 1 hours
        });
        sig = _sign(stealth.privateKey, intent, stealth.addr);
    }

    // live pool config: the app pins this pool, and the post-fee amount must clear the minimum
    function _expectedNet(uint256 balance, uint256 feeBps) internal view returns (uint256) {
        (address pool, uint256 minDeposit, uint256 vettingFeeBps) = IPPEntrypointConfigUsdc(PP_ENTRYPOINT).assetConfig(USDC);
        assertEq(pool, USDC_POOL, "entrypoint still maps USDC to the pool the app pins");
        uint256 deposit = balance - balance * feeBps / 10000;
        require(deposit >= minDeposit, "test amount below live minimum deposit");
        return deposit - deposit * vettingFeeBps / 10000;
    }

    function _runPoolDeposit(address sweeperImpl, string memory label, uint256 balance, uint256 feeBps) internal {
        Vm.Wallet memory stealth = vm.createWallet(label);
        deal(USDC, stealth.addr, balance);
        (StealthSweeperV2.SweepIntent memory intent, bytes memory sig) = _intent(stealth, feeBps, label);
        uint256 net = _expectedNet(balance, feeBps);
        uint256 poolBefore = IUsdcLike(USDC).balanceOf(USDC_POOL);
        address relayer = makeAddr(string.concat(label, "-relayer"));

        vm.recordLogs();
        vm.signAndAttachDelegation(sweeperImpl, stealth.privateKey);
        vm.prank(relayer, relayer);
        StealthSweeperV2(stealth.addr).executeSweep(intent, sig);

        assertEq(IUsdcLike(USDC).balanceOf(stealth.addr), 0, "stealth drained");
        assertEq(IUsdcLike(USDC).balanceOf(relayer), balance * feeBps / 10000, "token fee to tx.origin");
        assertEq(IUsdcLike(USDC).balanceOf(USDC_POOL) - poolBefore, net, "net USDC landed in the real pool");
        _checkDeposited(USDC_POOL, stealth.addr, net, intent.precommitment);
    }

    // the app finds the deposit by the pool's Deposited event: depositor is topic 1
    // (gp-inbox findDeposit), value + precommitment are in the data (app-core ppFindDeposit)
    function _checkDeposited(address pool, address depositor, uint256 net, uint256 precommitment) internal {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != pool || logs[i].topics.length != 2) continue;
            if (address(uint160(uint256(logs[i].topics[1]))) != depositor) continue;
            if (logs[i].data.length != 128) continue;
            (, , uint256 value, uint256 precom) = abi.decode(logs[i].data, (uint256, uint256, uint256, uint256));
            assertEq(value, net, "event value is the net escrowed amount");
            assertEq(precom, precommitment, "event carries the intent's precommitment");
            found = true;
        }
        assertTrue(found, "Deposited event emitted by the USDC pool");
    }

    function test_actionTwo_usdcPool_deployedSweeper() public {
        assertGt(DEPLOYED_SWEEPER_V2.code.length, 0, "SweeperV2 is deployed");
        _runPoolDeposit(DEPLOYED_SWEEPER_V2, "stealth-usdc-pool-deployed", 1000e6, 30);
    }

    function test_actionTwo_usdcPool_sourceBuild() public {
        StealthSweeperV2 fresh = new StealthSweeperV2();
        _runPoolDeposit(address(fresh), "stealth-usdc-pool-source", 1000e6, 30);
    }

    // the smallest balance the app offers the pool path for: post-fee just over 25 USDC
    function test_actionTwo_usdcPool_atMinimum() public {
        _runPoolDeposit(DEPLOYED_SWEEPER_V2, "stealth-usdc-pool-min", 25_075_226, 30);
    }

    function test_actionTwo_usdcPool_belowMinimumReverts() public {
        Vm.Wallet memory stealth = vm.createWallet("stealth-usdc-pool-low");
        address relayer = makeAddr("relayer-low");
        deal(USDC, stealth.addr, 20e6);
        StealthSweeperV2.SweepIntent memory intent = StealthSweeperV2.SweepIntent({
            action: 2, token: USDC, destination: address(0),
            precommitment: uint256(keccak256("low")) % SNARK_SCALAR_FIELD,
            feeBps: 30, deadline: block.timestamp + 1 hours
        });
        bytes memory sig = _sign(stealth.privateKey, intent, stealth.addr);
        vm.signAndAttachDelegation(DEPLOYED_SWEEPER_V2, stealth.privateKey);
        vm.prank(relayer, relayer);
        vm.expectRevert();
        StealthSweeperV2(stealth.addr).executeSweep(intent, sig);
    }
}
