cergyk

medium

# Rebalance may revert when sqrtPriceX96 > uint128

## Summary
The squaring of the variable sqrtPriceX96 may revert if it is large due to integer overflow, and prevent rebalancing of the vault.

## Vulnerability Detail
As can be seen here, FullMath library is used to make calculations on 512 bits numbers:
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/contracts/SimpleManager.sol#L184

However the first argument: `sqrtPriceX96 * sqrtPriceX96` is of type uint256 and can cause an overflow if 
`sqrtPriceX96 >= 2**128`

Please note that this has been reported during a previous audit:
https://gist.github.com/kassandraoftroy/25f7208adb770abee9f46978326cfb3f (1st issue)

But has incorrectly been marked as fixed when it was not, so it seems that this should be counted as a valid issue in the scope of this contest,
since without it, it would have stayed unnoticed.

## Impact
Rebalance may be impossible to execute when sqrtPriceX96 is large (gte than 2**128)

## Code Snippet

## Tool used

Manual Review

## Recommendation
```solidity
uint256 poolPrice = 
    FullMath.mulDiv(
        FullMath.mulDiv(
            sqrtPriceX96,
            10 ** token0Decimals,
            2 ** 192
        ), 
        sqrtPriceX96, 
        1
    );
```
or similar