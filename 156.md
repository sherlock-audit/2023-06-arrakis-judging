DadeKuma

medium

# ChainLinkOracle will return the wrong price for asset if the aggregator hits minAnswer

## Summary

Chainlink aggregators have a built-in circuit breaker if the price of an asset goes outside of a predetermined price band. 

The result is that if an asset experiences a huge drop in value (i.e. LUNA crash) the price of the oracle will continue to return the `minPrice` instead of the actual price of the asset. 

This would allow users to continue borrowing with the asset but at the wrong price. This is exactly what happened to [Venus on BSC when LUNA imploded](https://rekt.news/venus-blizz-rekt/).

## Vulnerability Detail

ChainlinkOracle uses Chainlink's feed price feed to obtain the price of the token:

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/contracts/oracles/ChainLinkOracle.sol#L71-L77

`ChainlinkAggregators` have a `minPrice` and a `maxPrice` circuit breakers built into them. This means that if the price of the asset drops below the `minPrice`, the protocol will continue to value the token at `minPrice` instead of its actual value. 

This will allow users to take out huge amounts of bad debt and bankrupt the protocol.

**Example**:
`token0` has a minPrice of $1. The price of `token0` drops to $0.10. The aggregator still returns $1 which is 10x its actual value.

In the past, we have seen similar reports, like this: https://github.com/sherlock-audit/2023-02-blueberry-judging/issues/18

## Impact

Medium, as it is a rare occurrence: in the event that an asset crashes (like what happened to LUNA), the protocol functions can be exploited thanks to the wrong oracle price.

## Code Snippet

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/contracts/oracles/ChainLinkOracle.sol#L71-L77

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/contracts/oracles/ChainLinkOracle.sol#L112-L118

## Tool used

Manual Review

## Recommendation

The oracle should check the returned answer against the minPrice/maxPrice and revert if the answer is outside of the bounds:

```diff
    try priceFeed.latestRoundData() returns (
        uint80,
        int256 price,
        uint256,
        uint256 updatedAt,
        uint80
    ) {

+   require(price < maxPrice, "max price exceeded");
+   require(price > minPrice, "min price exceeded");
```
