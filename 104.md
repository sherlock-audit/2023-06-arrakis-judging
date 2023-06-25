rvierdiiev

high

# SimpleManager.rebalance does incorrect price deviation check

## Summary
SimpleManager.rebalance does incorrect price deviation check, as it calculates wrong token0 price from uniswap.
## Vulnerability Detail
When manager is going to mint new liquidity, then `SimpleManager` checks if oracle price corresponds to current uniswap price.
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/contracts/SimpleManager.sol#L179-L194
```solidity
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
```
`sqrtPriceX96` is square root of token1/token0, so it shows price of token 0 and should be scaled in token1 decimals.
But the price form uniswap is transformed to amount with decimals of token0 instead of token1, while price from oracle is price of token0 in token1 decimals.
Thus, it's not correct to make deviation check on this prices as one is scaled as token0 and another is scaled as token1.
As result minting liquidity will not be possible, because deviation will be big likely.
## Impact
Minting of liquidity through the rebalance will not be possible.
## Code Snippet
Provided above
## Tool used

Manual Review

## Recommendation
Pool price should be scaled in token1 decimals
```solidity
uint256 poolPrice = FullMath.mulDiv(
                sqrtPriceX96 * sqrtPriceX96,
                10 ** token1Decimals,
                2 ** 192
            );
```