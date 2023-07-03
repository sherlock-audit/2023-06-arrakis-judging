Bauchibred

medium

# Uniswap oracle should not be used on L2s



## Summary

Arrakis is planned to be deployed on multiple Layer 2 (L2) networks. However, it is important to note that Uniswap advises against using their oracle on L2 networks, including Optimism and Arbitrum, due to the ease of manipulating price feeds in these environments. Therefore, it is recommended to refrain from utilizing Uniswap's oracle feature on Arbitrum until further updates or improvements are made to enhance oracle security.

## Vulnerability Detail

The information provided by the Uniswap team, as documented in the [Uniswap Oracle Integration on Layer 2 Rollups](https://docs.uniswap.org/concepts/protocol/oracle#oracles-integrations-on-layer-2-rollups) guide, primarily addresses the integration of Uniswap oracle on L2 Optimism. However, it is relevant to note that the same concerns apply to Arbitrum as well. Arbitrum's average block time is approximately 0.25 seconds, making it vulnerable to potential oracle price manipulation.

> ### Oracles Integrations on Layer 2 Rollups
>
> Optimism
> On Optimism, every transaction is confirmed as an individual block. The block.timestamp of these blocks, however, reflect the block.timestamp of the last L1 block ingested by the Sequencer. For this reason, Uniswap pools on Optimism are not suitable for providing oracle prices, as this high-latency block.timestamp update process makes the oracle much less costly to manipulate. In the future, it's possible that the Optimism block.timestamp will have much higher granularity (with a small trust assumption in the Sequencer), or that forced inclusion transactions will improve oracle security. For more information on these potential upcoming changes, please see the [Optimistic Specs repo](https://github.com/ethereum-optimism/optimistic-specs/discussions/23). **For the time being, usage of the oracle feature on Optimism should be avoided.**

## Impact

Easily Manipulated Oracle Data: Due to the specific characteristics of L2 networks, such as high-latency block.timestamp update processes, the Uniswap oracle becomes vulnerable to price manipulation. This manipulation can lead to inaccurate and unreliable price feeds, potentially resulting in significant financial losses for users relying on these price references.

## Code Snippet

[UniswapV3PoolOracle.sol]](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/contracts/oracles/UniswapV3PoolOracle.sol#L7-L33).

## Tool used

Manual Audit

## Recommendation

Until further updates or improvements are made to address the security concerns associated with Uniswap's oracle on Arbitrum, it is strongly recommended to refrain from utilizing the oracle feature in the current implementation.
