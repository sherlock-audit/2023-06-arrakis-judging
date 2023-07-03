lil.eth

high

# Using slot0 data could lead to price manipulations

## Summary

Usage of `slot0` is extremely easy to manipulate 

## Vulnerability Detail

Protocol uses Uniswap `slot0` function that returns the price from the last trade. This price could be manipulated in different ways, for example, through flash-loans. This could affect prices during rebalance calls.
- ArrakisV2Resolver.sol (not in scope)
- Underlying.sol#underlying() : (uint160 sqrtPriceX96, int24 tick, , , , , ) = underlying_.pool.slot0();
- Underlying.sol#underlyingMint() : (uint160 sqrtPriceX96, int24 tick, , , , , ) = underlying_.pool.slot0();
- simpleManager.sol#rebalance() : (sqrtPriceX96, , , , , , ) = pool.slot0();

## Impact

Price could be easily manipulated.
## Code Snippet
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/contracts/SimpleManager.sol#L181

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/libraries/Underlying.sol#L134

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/libraries/Underlying.sol#L167

## Tool used

Manual Review

## Recommendation
Consider using Uniswap TWAP prices instead of `slot0`.