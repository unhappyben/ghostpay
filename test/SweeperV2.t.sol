// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../SweeperV2.sol";
import "../BatchRelayer.sol";

interface IPPEntrypointConfig {
    function assetConfig(address asset) external view returns (address pool, uint256 minimumDepositAmount, uint256 vettingFeeBps);
}

interface ITestERC20 {
    function balanceOf(address account) external view returns (uint256);
}

/// Fork-only test suite. Nothing is ever broadcast: every test runs against a local
/// anvil fork of mainnet created from MAINNET_RPC.
///
/// Delegation approach: forge-std exposes the EIP-7702 cheatcodes
/// (vm.signAndAttachDelegation / vm.signDelegation + vm.attachDelegation), which make
/// the next call a type-4 transaction carrying the authorization(s), exactly like the
/// real relayer flow. Multiple attachDelegation calls stack onto the next call, which
/// is how the BatchRelayer test sweeps two EOAs in one transaction. If a future forge
/// drops these cheatcodes, the fallback is `vm.etch(stealth, address(sweeper).code)`
/// to simulate delegation (bytecode-identical execution context: address(this) is the
/// stealth EOA), documented here so the switch is mechanical.
contract SweeperV2Test is Test {
    StealthSweeperV2 sweeper;
    BatchRelayer batcher;

    address constant PP_ENTRYPOINT = 0x6818809EefCe719E480a7526D76bD3e561526b46;
    address constant NATIVE_ASSET = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE; // entrypoint's sentinel for ETH
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // mirrored from StealthSweeperV2: the frontend and relayer build these same bytes
    bytes32 constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant SWEEP_INTENT_TYPEHASH =
        keccak256("SweepIntent(uint8 action,address token,address destination,uint256 precommitment,uint256 feeBps,uint256 deadline)");

    function setUp() public {
        vm.createSelectFork(vm.envOr("MAINNET_RPC", string("https://eth.drpc.org")));
        sweeper = new StealthSweeperV2();
        batcher = new BatchRelayer();
    }

    // --- helpers ---

    function _digest(StealthSweeperV2.SweepIntent memory intent, address account) internal view returns (bytes32) {
        bytes32 domain = keccak256(abi.encode(
            DOMAIN_TYPEHASH, keccak256(bytes("GhostpaySweeper")), keccak256(bytes("1")), block.chainid, account
        ));
        bytes32 structHash = keccak256(abi.encode(
            SWEEP_INTENT_TYPEHASH,
            intent.action, intent.token, intent.destination, intent.precommitment, intent.feeBps, intent.deadline
        ));
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    function _sign(uint256 pk, StealthSweeperV2.SweepIntent memory intent, address account) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _digest(intent, account));
        return abi.encodePacked(r, s, v);
    }

    function _ethIntent(address destination, uint256 feeBps, uint256 deadline) internal pure returns (StealthSweeperV2.SweepIntent memory) {
        return StealthSweeperV2.SweepIntent({
            action: 0,
            token: address(0),
            destination: destination,
            precommitment: 0,
            feeBps: feeBps,
            deadline: deadline
        });
    }

    // --- (1) happy path: delegated EOA executes its own signed intent ---

    function test_executeSweepETH_happyPath() public {
        Vm.Wallet memory stealth = vm.createWallet("stealth-happy");
        address relayer = makeAddr("relayer");
        address dest = makeAddr("dest");
        vm.deal(stealth.addr, 1 ether);

        StealthSweeperV2.SweepIntent memory intent = _ethIntent(dest, 50, block.timestamp + 1 hours);
        bytes memory sig = _sign(stealth.privateKey, intent, stealth.addr);

        vm.signAndAttachDelegation(address(sweeper), stealth.privateKey);
        uint256 relayerBefore = relayer.balance;
        vm.prank(relayer, relayer); // msg.sender AND tx.origin = the runner EOA
        StealthSweeperV2(stealth.addr).executeSweep(intent, sig);

        assertEq(stealth.addr.balance, 0, "stealth drained");
        assertEq(dest.balance, 0.995 ether, "dest gets balance minus fee");
        assertEq(relayer.balance - relayerBefore, 0.005 ether, "tx.origin gets the fee");
    }

    // --- (2) wrong signer reverts ---

    function test_executeSweep_wrongSignerReverts() public {
        Vm.Wallet memory stealth = vm.createWallet("stealth-wrong");
        Vm.Wallet memory mallory = vm.createWallet("mallory");
        vm.deal(stealth.addr, 1 ether);

        StealthSweeperV2.SweepIntent memory intent = _ethIntent(makeAddr("dest"), 50, block.timestamp + 1 hours);
        // signed by mallory, not by the stealth key
        bytes memory sig = _sign(mallory.privateKey, intent, stealth.addr);

        vm.signAndAttachDelegation(address(sweeper), stealth.privateKey);
        vm.expectRevert("signer is not this account");
        StealthSweeperV2(stealth.addr).executeSweep(intent, sig);
    }

    // --- (3) expired deadline reverts ---

    function test_executeSweep_expiredDeadlineReverts() public {
        Vm.Wallet memory stealth = vm.createWallet("stealth-expired");
        vm.deal(stealth.addr, 1 ether);

        StealthSweeperV2.SweepIntent memory intent = _ethIntent(makeAddr("dest"), 50, block.timestamp - 1);
        bytes memory sig = _sign(stealth.privateKey, intent, stealth.addr);

        vm.signAndAttachDelegation(address(sweeper), stealth.privateKey);
        vm.expectRevert("intent expired");
        StealthSweeperV2(stealth.addr).executeSweep(intent, sig);
    }

    // --- (4) feeBps > 1000 reverts ---

    function test_executeSweep_feeTooHighReverts() public {
        Vm.Wallet memory stealth = vm.createWallet("stealth-fee");
        vm.deal(stealth.addr, 1 ether);

        StealthSweeperV2.SweepIntent memory intent = _ethIntent(makeAddr("dest"), 1001, block.timestamp + 1 hours);

        vm.signAndAttachDelegation(address(sweeper), stealth.privateKey);
        vm.expectRevert("fee too high");
        StealthSweeperV2(stealth.addr).executeSweep(intent, new bytes(65)); // reverts before the sig is even read
    }

    // --- signature is bound to exactly one stealth account (domain verifyingContract) ---

    function test_executeSweep_signatureBoundToAccount() public {
        Vm.Wallet memory stealthA = vm.createWallet("stealth-A");
        Vm.Wallet memory stealthB = vm.createWallet("stealth-B");
        vm.deal(stealthB.addr, 1 ether);

        // signed by A's key over A's domain, replayed against B's delegated account
        StealthSweeperV2.SweepIntent memory intent = _ethIntent(makeAddr("dest"), 50, block.timestamp + 1 hours);
        bytes memory sig = _sign(stealthA.privateKey, intent, stealthA.addr);

        vm.signAndAttachDelegation(address(sweeper), stealthB.privateKey);
        vm.expectRevert("signer is not this account");
        StealthSweeperV2(stealthB.addr).executeSweep(intent, sig);
    }

    // --- (5) exact fee math, non-round numbers, including the tx.origin payout ---

    function test_executeSweepETH_exactFeeMath() public {
        Vm.Wallet memory stealth = vm.createWallet("stealth-math");
        address relayer = makeAddr("relayer");
        address dest = makeAddr("dest");
        vm.deal(stealth.addr, 3.7 ether);

        StealthSweeperV2.SweepIntent memory intent = _ethIntent(dest, 999, block.timestamp + 1 hours);
        bytes memory sig = _sign(stealth.privateKey, intent, stealth.addr);

        uint256 expectedFee = 3.7 ether * 999 / 10000; // 0.36963 ether
        vm.signAndAttachDelegation(address(sweeper), stealth.privateKey);
        uint256 relayerBefore = relayer.balance;
        vm.prank(relayer, relayer);
        StealthSweeperV2(stealth.addr).executeSweep(intent, sig);

        assertEq(stealth.addr.balance, 0);
        assertEq(dest.balance, 3.7 ether - expectedFee);
        assertEq(relayer.balance - relayerBefore, expectedFee, "fee paid to tx.origin, not msg.sender");
    }

    // --- (6) Privacy Pools ETH deposit lands value in the real mainnet entrypoint ---

    function test_executeSweep_privacyPoolsDeposit_realEntrypoint() public {
        Vm.Wallet memory stealth = vm.createWallet("stealth-pp");
        address relayer = makeAddr("relayer");
        vm.deal(stealth.addr, 1 ether);

        // precommitment must be inside the snark scalar field
        uint256 precommitment = uint256(keccak256("ghostpay-test-precommitment")) % SNARK_SCALAR_FIELD;
        StealthSweeperV2.SweepIntent memory intent = StealthSweeperV2.SweepIntent({
            action: 1,
            token: address(0),
            destination: address(0),
            precommitment: precommitment,
            feeBps: 100,
            deadline: block.timestamp + 1 hours
        });
        bytes memory sig = _sign(stealth.privateKey, intent, stealth.addr);

        // read the live config: pool address, minimum deposit, vetting fee
        (address pool, uint256 minDeposit, uint256 vettingFeeBps) =
            IPPEntrypointConfig(PP_ENTRYPOINT).assetConfig(NATIVE_ASSET);
        uint256 depositValue = 1 ether - (1 ether * 100 / 10000); // balance minus relayer fee
        require(depositValue >= minDeposit, "test amount below live minimum deposit");
        uint256 vettingFee = depositValue * vettingFeeBps / 10000;

        uint256 poolBefore = pool.balance;
        uint256 entrypointBefore = PP_ENTRYPOINT.balance;

        vm.signAndAttachDelegation(address(sweeper), stealth.privateKey);
        vm.prank(relayer, relayer);
        StealthSweeperV2(stealth.addr).executeSweep(intent, sig);

        assertEq(stealth.addr.balance, 0, "stealth drained");
        assertEq(pool.balance - poolBefore, depositValue - vettingFee, "net value landed in the real PP pool");
        assertEq(PP_ENTRYPOINT.balance - entrypointBefore, vettingFee, "entrypoint retained the vetting fee");
        assertEq(relayer.balance, 0.01 ether, "relayer fee still paid to tx.origin");
    }

    // --- (7) BatchRelayer sweeps two delegated EOAs in one call ---

    function test_batchRelayer_twoEOAsOneCall() public {
        Vm.Wallet memory s1 = vm.createWallet("stealth-b1");
        Vm.Wallet memory s2 = vm.createWallet("stealth-b2");
        address relayer = makeAddr("relayer");
        address dest1 = makeAddr("dest1");
        address dest2 = makeAddr("dest2");
        vm.deal(s1.addr, 1 ether);
        vm.deal(s2.addr, 2 ether);

        StealthSweeperV2.SweepIntent memory i1 = _ethIntent(dest1, 25, block.timestamp + 1 hours);
        StealthSweeperV2.SweepIntent memory i2 = _ethIntent(dest2, 100, block.timestamp + 1 hours);
        bytes memory sig1 = _sign(s1.privateKey, i1, s1.addr);
        bytes memory sig2 = _sign(s2.privateKey, i2, s2.addr);

        // both authorizations attach to the next call: one type-4 tx, two delegations
        vm.attachDelegation(vm.signDelegation(address(sweeper), s1.privateKey));
        vm.attachDelegation(vm.signDelegation(address(sweeper), s2.privateKey));

        address[] memory targets = new address[](2);
        targets[0] = s1.addr;
        targets[1] = s2.addr;
        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeCall(StealthSweeperV2.executeSweep, (i1, sig1));
        datas[1] = abi.encodeCall(StealthSweeperV2.executeSweep, (i2, sig2));

        vm.prank(relayer, relayer);
        batcher.relay(targets, datas);

        assertEq(s1.addr.balance, 0);
        assertEq(s2.addr.balance, 0);
        assertEq(dest1.balance, 1 ether - (1 ether * 25 / 10000));
        assertEq(dest2.balance, 2 ether - (2 ether * 100 / 10000));
        assertEq(relayer.balance, (1 ether * 25 / 10000) + (2 ether * 100 / 10000), "both fees to tx.origin");
    }

    // --- relay() is all-or-nothing, relaySkipFailures() reports and continues ---

    function test_batchRelayer_relayRevertsOnAnyFailure() public {
        Vm.Wallet memory s1 = vm.createWallet("stealth-r1");
        Vm.Wallet memory s2 = vm.createWallet("stealth-r2");
        Vm.Wallet memory mallory = vm.createWallet("mallory-r");
        vm.deal(s1.addr, 1 ether);
        vm.deal(s2.addr, 1 ether);

        StealthSweeperV2.SweepIntent memory i1 = _ethIntent(makeAddr("d1"), 0, block.timestamp + 1 hours);
        StealthSweeperV2.SweepIntent memory i2 = _ethIntent(makeAddr("d2"), 0, block.timestamp + 1 hours);
        bytes memory sig1 = _sign(s1.privateKey, i1, s1.addr);
        bytes memory sig2 = _sign(mallory.privateKey, i2, s2.addr); // bad: signed by the wrong key

        vm.attachDelegation(vm.signDelegation(address(sweeper), s1.privateKey));
        vm.attachDelegation(vm.signDelegation(address(sweeper), s2.privateKey));

        address[] memory targets = new address[](2);
        targets[0] = s1.addr;
        targets[1] = s2.addr;
        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeCall(StealthSweeperV2.executeSweep, (i1, sig1));
        datas[1] = abi.encodeCall(StealthSweeperV2.executeSweep, (i2, sig2));

        vm.expectRevert("signer is not this account");
        batcher.relay(targets, datas);
    }

    function test_batchRelayer_skipFailuresEmitsAndContinues() public {
        Vm.Wallet memory s1 = vm.createWallet("stealth-s1");
        Vm.Wallet memory s2 = vm.createWallet("stealth-s2");
        Vm.Wallet memory mallory = vm.createWallet("mallory-s");
        address dest1 = makeAddr("dest-s1");
        vm.deal(s1.addr, 1 ether);
        vm.deal(s2.addr, 1 ether);

        StealthSweeperV2.SweepIntent memory i1 = _ethIntent(dest1, 0, block.timestamp + 1 hours);
        StealthSweeperV2.SweepIntent memory i2 = _ethIntent(makeAddr("d2"), 0, block.timestamp + 1 hours);
        bytes memory sig1 = _sign(s1.privateKey, i1, s1.addr);
        bytes memory sig2 = _sign(mallory.privateKey, i2, s2.addr); // bad

        vm.attachDelegation(vm.signDelegation(address(sweeper), s1.privateKey));
        vm.attachDelegation(vm.signDelegation(address(sweeper), s2.privateKey));

        address[] memory targets = new address[](2);
        targets[0] = s1.addr;
        targets[1] = s2.addr;
        bytes[] memory datas = new bytes[](2);
        datas[0] = abi.encodeCall(StealthSweeperV2.executeSweep, (i1, sig1));
        datas[1] = abi.encodeCall(StealthSweeperV2.executeSweep, (i2, sig2));

        vm.expectEmit(true, true, false, false, address(batcher));
        emit BatchRelayer.RelayFailed(1, s2.addr, "");
        batcher.relaySkipFailures(targets, datas);

        assertEq(s1.addr.balance, 0, "good sweep went through");
        assertEq(dest1.balance, 1 ether);
        assertEq(s2.addr.balance, 1 ether, "bad sweep was skipped, funds untouched");
    }

    // --- bonus: token sweep (action 3) with real mainnet USDC ---

    function test_executeSweepToken_USDC() public {
        Vm.Wallet memory stealth = vm.createWallet("stealth-usdc");
        address relayer = makeAddr("relayer");
        address dest = makeAddr("dest-usdc");
        deal(USDC, stealth.addr, 1000e6);

        StealthSweeperV2.SweepIntent memory intent = StealthSweeperV2.SweepIntent({
            action: 3,
            token: USDC,
            destination: dest,
            precommitment: 0,
            feeBps: 100,
            deadline: block.timestamp + 1 hours
        });
        bytes memory sig = _sign(stealth.privateKey, intent, stealth.addr);

        vm.signAndAttachDelegation(address(sweeper), stealth.privateKey);
        vm.prank(relayer, relayer);
        StealthSweeperV2(stealth.addr).executeSweep(intent, sig);

        assertEq(ITestERC20(USDC).balanceOf(stealth.addr), 0);
        assertEq(ITestERC20(USDC).balanceOf(dest), 990e6, "dest gets balance minus fee");
        assertEq(ITestERC20(USDC).balanceOf(relayer), 10e6, "token fee to tx.origin");
    }
}
