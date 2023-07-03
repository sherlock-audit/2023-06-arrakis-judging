ast3ros

medium

# No slippage protection when adding liquidity to UniswapV3 pool

## Summary

In ArrakisV2 vault, when minting Arrakis V2 shares, the underlying assets are deposited to UniswapV3 pool to provide liquidity. However, there is no slippage protection.

## Vulnerability Detail

If the total supply is more than 0, the deposited underlying assets are used to provide liquidity to UniswapV3 pool:

        pool.mint(me, range.lowerTick, range.upperTick, liquidity, "");

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L149

However, there are no parameters for `minDeposit0` and `minDeposit1`, which are used to prevent slippage. The function without slippage protection could be vulnerable to a front-running attack designed to execute the mint call at an unfavorable price.
 
For details of slippage protection when minting, please see:

https://docs.uniswap.org/contracts/v3/guides/providing-liquidity/mint-a-position#calling-mint
https://uniswapv3book.com/docs/milestone_3/slippage-protection/#slippage-protection-in-minting

## Impact

The function is exposed to front-running risk and could mint at a distorted price.

## Code Snippet

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L149

## Tool used

Manual Review

## Recommendation

Estimate the `minDeposit0` and `minDeposit1` like the mint part in the rebalance function. Revert if the total amount of token0 and token1 used is less than the minDeposit0 and minDeposit1.