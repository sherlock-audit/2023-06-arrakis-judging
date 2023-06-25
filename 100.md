rvierdiiev

medium

# ArrakisV2Router.addLiquidity needs deadline protection

## Summary
ArrakisV2Router.addLiquidity needs deadline protection.
## Vulnerability Detail
`ArrakisV2Router.addLiquidity` [has slippage protection](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#L79-L84). But this is not enough. Attacker still can run this tx in his favour, by caching it in mempool and run later. In order to avoid that deadline param is needed to be provided by user.
## Impact
Tx can be executed with outdated prices.
## Code Snippet
Provided above
## Tool used

Manual Review

## Recommendation
Add deadline param.