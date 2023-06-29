0xDjango

medium

# Update to `managerFeeBPS` applied to pending tokens yet to be claimed

## Summary
A manager (malicious or not) can update the `managerFeeBPS` by calling `ArrakisV2.setManagerFeeBPS()`. The newly-updated `managerFeeBPS` will be retroactively applied to the pending fees yet to be claimed by the `ArrakisV2` contract.

## Vulnerability Detail
Whenever UniV3 fees are collected (via `burn()` or `rebalance()`), the manager fees are applied to the received pending tokens.

```solidity
function _applyFees(uint256 fee0_, uint256 fee1_) internal {
    uint16 mManagerFeeBPS = managerFeeBPS;
    managerBalance0 += (fee0_ * mManagerFeeBPS) / hundredPercent;
    managerBalance1 += (fee1_ * mManagerFeeBPS) / hundredPercent;
}
```

Since the manager can update the `managerFeeBPS` whenever, this calculation can be altered to take up to 100% of the pending fees in favor of the manager.

```solidity
function setManagerFeeBPS(uint16 managerFeeBPS_) external onlyManager {
    require(managerFeeBPS_ <= 10000, "MFO");
    managerFeeBPS = managerFeeBPS_;
    emit LogSetManagerFeeBPS(managerFeeBPS_);
}
```

## Impact
- Manager's ability to intentionally or accidently steal pending fees owed to stakers

## Code Snippet
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2Storage.sol#L218-L222

## Tool used
Manual Review

## Recommendation
Fees should be collected at the start of execution within the `setManagerFeeBPS()` function. This effectively checkpoints the fees properly, prior to updating the `managerFeeBPS` variable.
