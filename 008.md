0xRobocop

medium

# Then getAmountsForDelta function at Underlying.sol is implemented incorrectly

## Summary

The function `getAmountsForDelta()` at the `Underlying.sol` contract is used to compute the quantity of `token0` and `token1` to add to the position given a delta of liquidity. These quantities depend on the delta of liquidity, the current tick and the ticks of the range boundaries. Actually, `getAmountsForDelta()` uses the sqrt prices instead of the ticks, but they are equivalent since each tick represents a sqrt price.

There exists 3 cases:

- The current tick is outside the range from the left, this means only `token0` should be added.
- The current tick is within the range, this means both `token0` and `token1` should be added.
- The current tick is outside the range from the right, this means only `token1` should be added.

## Vulnerability Detail

The issue on the implementation is on the first case, which is coded as follows:

```solidity
if (sqrtRatioX96 <= sqrtRatioAX96) {
      amount0 = SafeCast.toUint256(
          SqrtPriceMath.getAmount0Delta(
               sqrtRatioAX96,
               sqrtRatioBX96,
               liquidity
          )
      );
} 
```

The implementation says that if the current price is equal to the price of the lower tick, it means that it is outside of the range and hence only `token0` should be added to the position. 

But for the UniswapV3 implementation, the current price must be lower in order to consider it outside:

```solidity
if (_slot0.tick < params.tickLower) {
   // current tick is below the passed range; liquidity can only become in range by crossing from left to
   // right, when we'll need _more_ token0 (it's becoming more valuable) so user must provide it
   amount0 = SqrtPriceMath.getAmount0Delta(
          TickMath.getSqrtRatioAtTick(params.tickLower),
          TickMath.getSqrtRatioAtTick(params.tickUpper),
          params.liquidityDelta
    );
}
```
[Reference](https://github.com/Uniswap/v3-core/blob/d8b1c635c275d2a9450bd6a78f3fa2484fef73eb/contracts/UniswapV3Pool.sol#L328-L336)

## Impact

When the current price is equal to the left boundary of the range, the uniswap pool will request both `token0` and `token1`, but arrakis will only request from the user `token0` so the pool will lose some `token1` if it has enough to cover it.

## Code Snippet

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/libraries/Underlying.sol#LL311-L318

## Tool used

Manual Review

## Recommendation

Change from:

```solidity
// @audit-issue Change <= to <.
if (sqrtRatioX96 <= sqrtRatioAX96) {
     amount0 = SafeCast.toUint256(
        SqrtPriceMath.getAmount0Delta(
           sqrtRatioAX96,
           sqrtRatioBX96,
           liquidity
         )
     );
}
```

to:

```solidity
if (sqrtRatioX96 < sqrtRatioAX96) {
     amount0 = SafeCast.toUint256(
        SqrtPriceMath.getAmount0Delta(
           sqrtRatioAX96,
           sqrtRatioBX96,
           liquidity
         )
     );
}
```