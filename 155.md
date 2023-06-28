DadeKuma

medium

# First minter in a vault doesn't add any liquidity to the pool

## Summary
The first minter in an `ArrakisV2` will not add any liquidity to the pool due to how the logic works.

## Vulnerability Detail

Suppose the following flow:

1. A user calls `mint` on a vault with zero `totalSupply`, so `isTotalSupplyGtZero = false`:

```solidity
bool isTotalSupplyGtZero = ts > 0;
```
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L66


2. Following the logic, `isTotalSupplyGtZero` will stay false as it is the same value and it's not recalculated:

```solidity
if (isTotalSupplyGtZero) {
    for (uint256 i; i < _ranges.length; i++) {
        ...
        pool.mint(me, range.lowerTick, range.upperTick, liquidity, "");
    }
}
```
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L127-L150

3. This results in the pool not receiving any liquidity. As an immediate effect, if the user would withdraw by calling `burn`, no fees would be applied as the pool liquidity is zero:

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L143

4. If someone else mints more shares, they will add some liquidity to the pool, but the last user that withdraws after the liquidity is zero will not pay any withdrawal fees, as the initial deposit is not counted towards the total liquidity.

## Impact

Medium, as the last user that calls `burn` after the pool liquidity is zero, will not pay any withdrawal/burn fees for their deposit.

## Code Snippet

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L127-L150

## Tool used

Manual Review

## Recommendation

Consider recalculating the `totalSupply` in mint, as `isTotalSupplyGtZero` is stale, to add the first deposit as liquidity to the pool:
```diff
-    if (isTotalSupplyGtZero) {
+    if (totalSupply() > 0) {
        for (uint256 i; i < _ranges.length; i++) {
            Range memory range = _ranges[i];
            IUniswapV3Pool pool = IUniswapV3Pool(
                factory.getPool(
                    address(token0),
                    address(token1),
                    range.feeTier
                )
            );
            ...
        }
    }
```
