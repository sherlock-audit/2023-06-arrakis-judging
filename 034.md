eyexploit

medium

# Lack of zero liquidity check during pool minting process

## Summary
mintAmount_ may round down the liquidity to zero for small value, causing pool to revert the mint txn.

## Vulnerability Detail
In the ArrakisV2#mint(), if the `mintAmount_` passes is small then due to solidity rounding issue, liquidity to be mint will round down to 0. Hence causing revert to txn. 

```solidity
    uint128 liquidity = Position.getLiquidityByRange(
        pool,
        me,
        range.lowerTick,
        range.upperTick
    );
    if (liquidity == 0) continue;

    liquidity = SafeCast.toUint128(
        FullMath.mulDiv(liquidity, mintAmount_, ts)  // @audit-issue round down to zero
    );

    pool.mint(me, range.lowerTick, range.upperTick, liquidity, ""); 
```

## Impact

## Code Snippet
https://github.com/sherlock-audit/2023-06-arrakis/blob/9594cf930307ebbfe5cae4f8ad9e9b40b26c9fec/v2-core/contracts/ArrakisV2.sol#L145-L147

## Tool used

Manual Review

## Recommendation

Consider putting zero liquidity check after the liquidity calculation

```solidity

    liquidity = SafeCast.toUint128(
        FullMath.mulDiv(liquidity, mintAmount_, ts)
    );

    if (liquidity == 0) continue;

    pool.mint(me, range.lowerTick, range.upperTick, liquidity, ""); 
```