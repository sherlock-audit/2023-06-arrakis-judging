Bauchibred

medium

# Using `slot0` to determine deviation is not ideal


## Summary

The `rebalance` function in the SimpleManager contract utilizes the most recent price point `slot0` to determine the current pool price and subsequently, the deviation from the oracle price. However, `slot0` is the most recent data point and is therefore extremely easy to manipulate, meaning that the price deviation might be inaccurate, which could potentially lead to incorrect rebalancing and Denial of Service (DoS) due to failure of deviation checks.

```solidity
require(deviation <= maxDeviation_, "maxDeviation");
```

## Vulnerability Detail

In the SimpleManager.sol contract, the `rebalance` function retrieves the current pool price using `slot0` that represents the most recent price point. The function `_checkDeviation` then calculates the deviation of this current price from the oracle price.

Given `slot0`'s susceptibility to manipulation, the deviation calculation might be skewed. This is particularly crucial because the deviation is extensively used in the protocol to maintain balance and perform vital operations.

For example, if the deviation is larger than the `maxDeviation_` parameter in `_checkDeviation` function, the function fails, potentially causing a DoS in the contract. This is due to the line `require(deviation <= maxDeviation_, "maxDeviation");` in the `_checkDeviation` function.

## Impact

The usage of `slot0` to determine deviation could potentially allow malicious actors to manipulate the deviation calculation by altering the most recent price. As a consequence, this might lead to incorrect rebalancing operations, resulting in an inaccurate state of the contract, if the deviation check fails due to the manipulated deviation exceeding the maximum allowed deviation.

## Code Snippet

[rebalance()](https://github.com/sherlock-audit/2023-06-arrakis/blob/9594cf930307ebbfe5cae4f8ad9e9b40b26c9fec/v2-manager-templates/contracts/SimpleManager.sol#L128-L214) and [`_checkDeviation()`](https://github.com/sherlock-audit/2023-06-arrakis/blob/9594cf930307ebbfe5cae4f8ad9e9b40b26c9fec/v2-manager-templates/contracts/SimpleManager.sol#L366-L385)

```solidity
function rebalance(
    address vault_,
    Rebalance calldata rebalanceParams_
) external {
    ...
    IUniswapV3Pool pool = IUniswapV3Pool(
        _getPool(
            token0,
            token1,
            rebalanceParams_.mints[i].range.feeTier
        )
    );
    uint256 sqrtPriceX96;
    (sqrtPriceX96, , , , , , ) = pool.slot0();
    uint256 poolPrice = FullMath.mulDiv(
        sqrtPriceX96 * sqrtPriceX96,
        10 ** token0Decimals,
        2 ** 192
    );
    _checkDeviation(
        poolPrice,
        oraclePrice,
        vaultInfo.maxDeviation,
        token1Decimals
    );
    ...ommited for brevity
}
function _checkDeviation(
    uint256 currentPrice_,
    uint256 oraclePrice_,
    uint24 maxDeviation_,
    uint8 priceDecimals_
) internal pure {
    ...ommited for brevity
    require(deviation <= maxDeviation_, "maxDeviation");
}
```

## Tool used

Manual Audit

## Recommendation

Considering the potential risks associated with using `slot0` to calculate deviation, implementing a Time-Weighted Average Price (TWAP) to determine the price is recommended. By providing a more accurate and harder to manipulate price point, TWAP would yield a more accurate deviation calculation. This would reduce the possibility of incorrect rebalancing and the risk of DoS attacks.

NB: As the Uniswap team have warned [here](https://docs.uniswap.org/concepts/protocol/oracle#oracles-integrations-on-layer-2-rollups) there are issues if TWAP is going to be implemented on an L2 and these should be taken into account.
