// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../PayAndAnnounce.sol";

interface ITestERC20PA {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// Receiver whose receive() always reverts, used to prove atomicity.
contract RevertingReceiver {
    receive() external payable {
        revert("no ETH accepted");
    }
}

/// Fork-only test suite. Nothing is ever broadcast: every test runs against a local
/// anvil fork of mainnet created from MAINNET_RPC, so the announce calls hit the real
/// deployed ERC-5564 singleton at ANNOUNCER and the token test moves real mainnet USDC.
contract PayAndAnnounceTest is Test {
    PayAndAnnounce payer;

    address constant ANNOUNCER = 0x55649E01B5Df198D18D95b5cc5051630cfD45564;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    // mirrored from the singleton: the caller topic is PayAndAnnounce itself, since
    // the contract, not the EOA, is the immediate msg.sender of announce()
    event Announcement(
        uint256 indexed schemeId,
        address indexed stealthAddress,
        address indexed caller,
        bytes ephemeralPubKey,
        bytes metadata
    );

    bytes constant EPH_PUB = hex"02a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9001";
    bytes constant METADATA = hex"01deadbeefcafe";

    function setUp() public {
        vm.createSelectFork(vm.envOr("MAINNET_RPC", string("https://eth.drpc.org")));
        payer = new PayAndAnnounce();
    }

    // --- (1) happy path: one call emits the singleton Announcement and delivers ETH ---

    function test_pay_announcesAndDeliversETH() public {
        address stealth = makeAddr("stealth-eth");
        address sender = makeAddr("sender-eth");
        vm.deal(sender, 1 ether);
        // fork quirk: the deterministic deploy address of the first contract out of any
        // test contract holds real mainnet dust, so compare against the starting balance
        uint256 payerBefore = address(payer).balance;

        vm.expectEmit(true, true, true, true, ANNOUNCER);
        emit Announcement(1, stealth, address(payer), EPH_PUB, METADATA);

        vm.prank(sender);
        payer.pay{value: 0.42 ether}(payable(stealth), EPH_PUB, METADATA);

        assertEq(stealth.balance, 0.42 ether, "full msg.value arrived at the stealth address");
        assertEq(sender.balance, 0.58 ether);
        assertEq(address(payer).balance, payerBefore, "contract holds no new funds");
    }

    // --- (2) reverting receiver: the whole call reverts, so no announcement persists ---

    function test_pay_revertingReceiverReverts_noAnnouncement() public {
        RevertingReceiver recv = new RevertingReceiver();
        address sender = makeAddr("sender-revert");
        address goodStealth = makeAddr("stealth-good");
        vm.deal(sender, 1 ether);
        uint256 recvBefore = address(recv).balance; // fork dust, as above

        vm.prank(sender);
        vm.expectRevert("ETH transfer failed");
        payer.pay{value: 0.5 ether}(payable(address(recv)), EPH_PUB, METADATA);

        // state rolled back: sender refunded, receiver got nothing
        assertEq(sender.balance, 1 ether, "sender refunded: announce + payment are atomic");
        assertEq(address(recv).balance, recvBefore);

        // logs roll back with state: if the reverted announce had persisted, the next
        // Announcement from the singleton would be that one, and this expectEmit (with
        // a different stealth and ephemeral key) would fail instead of matching.
        bytes memory eph2 = hex"03ffa1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9002";
        vm.expectEmit(true, true, true, true, ANNOUNCER);
        emit Announcement(1, goodStealth, address(payer), eph2, METADATA);
        vm.prank(sender);
        payer.pay{value: 0.25 ether}(payable(goodStealth), eph2, METADATA);

        assertEq(goodStealth.balance, 0.25 ether);
        assertEq(sender.balance, 0.75 ether, "only the successful payment left the sender");
    }

    // --- (3) payToken: real mainnet USDC, approve then pay + announce in one call ---

    function test_payToken_USDC_announcesAndTransfers() public {
        address stealth = makeAddr("stealth-usdc");
        address sender = makeAddr("sender-usdc");
        deal(USDC, sender, 1000e6);

        // the required prior approve (in production: separate tx, or a 5792 batch)
        vm.prank(sender);
        ITestERC20PA(USDC).approve(address(payer), 250e6);

        vm.expectEmit(true, true, true, true, ANNOUNCER);
        emit Announcement(1, stealth, address(payer), EPH_PUB, METADATA);

        vm.prank(sender);
        payer.payToken(USDC, stealth, 250e6, EPH_PUB, METADATA);

        assertEq(ITestERC20PA(USDC).balanceOf(stealth), 250e6, "USDC landed at the stealth address");
        assertEq(ITestERC20PA(USDC).balanceOf(sender), 750e6);
        assertEq(ITestERC20PA(USDC).balanceOf(address(payer)), 0, "contract holds no tokens");
    }

    // --- (4) payToken without approve reverts, and no announcement persists ---

    function test_payToken_noAllowanceReverts_noAnnouncement() public {
        address stealth = makeAddr("stealth-noallow");
        address sender = makeAddr("sender-noallow");
        deal(USDC, sender, 1000e6);

        vm.prank(sender);
        vm.expectRevert();
        payer.payToken(USDC, stealth, 250e6, EPH_PUB, METADATA);

        assertEq(ITestERC20PA(USDC).balanceOf(stealth), 0);
        assertEq(ITestERC20PA(USDC).balanceOf(sender), 1000e6, "sender balance untouched");
    }
}
