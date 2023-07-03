ast3ros

medium

# outdated variable is not effective to check price feed timeliness

## Summary

In ChainlinkOraclePivot, it uses one `outdated` variable to check if the two price feeds are outdated. However, this is not effective because the price feeds have different update frequencies.

## Vulnerability Detail

Let's have an example: 

In Polygon mainnet, ChainlinkOraclePivot uses two Chainlink price feeds: MATIC/ETH and ETH/USD.
 
The setup can be the same in this test case:
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/test/foundry/ChainLinkOraclePivotWrapper.t.sol#L49-L63

We can see that 
- priceFeedA: MATIC/ETH price feed has a heartbeat of 86400s (https://data.chain.link/polygon/mainnet/crypto-eth/matic-eth).
- priceFeedB: ETH/USD price feed has a heartbeat of 27s (https://data.chain.link/polygon/mainnet/crypto-usd/eth-usd).

In function `_getLatestRoundData`, both price feeds use the same `outdated` variable.
- If we set the `outdated` variable to 27s, the priceFeedA will revert most of the time since it is too short for the 86400s heartbeat.
- If we set the `outdated` variable to 86400s, the priceFeedB can have a very outdated value without revert.

```javascript
        try priceFeedA.latestRoundData() returns (
            uint80,
            int256 price,
            uint256,
            uint256 updatedAt,
            uint80
        ) {
            require(
                block.timestamp - updatedAt <= outdated, // solhint-disable-line not-rely-on-time
                "ChainLinkOracle: priceFeedA outdated."
            );

            priceA = SafeCast.toUint256(price);
        } catch {
            revert("ChainLinkOracle: price feed A call failed.");
        }

        try priceFeedB.latestRoundData() returns (
            uint80,
            int256 price,
            uint256,
            uint256 updatedAt,
            uint80
        ) {
            require(
                block.timestamp - updatedAt <= outdated, // solhint-disable-line not-rely-on-time
                "ChainLinkOracle: priceFeedB outdated."
            );

            priceB = SafeCast.toUint256(price);
        } catch {
            revert("ChainLinkOracle: price feed B call failed.");
        }
```

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/contracts/oracles/ChainLinkOraclePivot.sol#L239-L271

## Impact

The `outdated` variable is not effective to check the timeliness of prices. It can allow stale prices in one price feed or always revert in another price feed.

## Code Snippet

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/contracts/oracles/ChainLinkOraclePivot.sol#L31
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/contracts/oracles/ChainLinkOraclePivot.sol#L239-L271

## Tool used

Manual Review

## Recommendation

Having two `outdated` values for each price feed A and B.