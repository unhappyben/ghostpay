// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BatchRelayer — fan-out dispatcher for batched EIP-7702 sweeps.
/// @dev One type-4 transaction carries N 7702 authorizations in its authorizationList
///      and calls relay() here: every stealth EOA delegates to StealthSweeperV2, then
///      each payload (executeSweep) runs against its own EOA. N stealth EOAs swept in
///      a single transaction, one gas payment. Relayer fees still land on tx.origin
///      (the runner EOA), not on this contract, because executeSweep pays tx.origin.
///      Unlike the sweeper, this contract executes as ITSELF, so plain logic is fine.
contract BatchRelayer {
    event RelayFailed(uint256 indexed index, address indexed target, bytes reason);

    /// All-or-nothing: any failed inner call reverts the whole batch, bubbling the
    /// inner revert reason.
    function relay(address[] calldata targets, bytes[] calldata datas) external {
        require(targets.length == datas.length, "length mismatch");
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, bytes memory ret) = targets[i].call(datas[i]);
            if (!ok) {
                assembly { revert(add(ret, 0x20), mload(ret)) }
            }
        }
    }

    /// Best-effort: failures are skipped and reported, one RelayFailed event each.
    function relaySkipFailures(address[] calldata targets, bytes[] calldata datas) external {
        require(targets.length == datas.length, "length mismatch");
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok, bytes memory ret) = targets[i].call(datas[i]);
            if (!ok) emit RelayFailed(i, targets[i], ret);
        }
    }
}
