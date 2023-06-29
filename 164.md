0x52

medium

# Slippage protection for ArrakisV2Router#addLiquidity can be abused if the vault is active in more than one fee tier

## Summary

When adding liquidity to a vault via the ArrakisV2Router, amounts in and shares received are validated against parameters to ensure that there hasn't been any manipulation of the underlying pools. This is how typical LP is validated but due to the relative nature of a vault share this approach doesn't work.

## Vulnerability Detail

[ArrakisV2Router.sol#L79-L84](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#L79-L84)

        require(
            amount0 >= params_.amount0Min &&
                amount1 >= params_.amount1Min &&
                sharesReceived >= params_.amountSharesMin,
            "below min amounts"
        );
        
The checks above are intended to protect against slippage, however they can bypassed as long as the vault is entered into at least 2 different fee tiers. By sandwiching the LP being added in opposite directions across the two pools all the slippage requirements can be met while extracting value from the user.

For simplicity of the math we will assume the following:
    The vault owns all LP in the underlying pool
    LP is deployed over the entire range of the pool
    TokenX = $10 TokenY = $100

Assume the vault already has 100 shares and a user wants 10 shares and to deploy a minimum of 200 TokenX and 20 TokenY

1 - Pool starting values:

    Pool 1
        Token X: 1000
        Token Y: 100
    Pool 2
        Token X: 1000
        Token Y: 100
    
2 - Attacker moves price. The attacker sandwich attacks each pool, pushing it off axis:

    Pool 1
        Token X: 1111.1
        Token Y: 90
    Pool 2
        Token X: 909.1
        Token Y: 110
    Attacker
        Token X: -20.2 (90.9 - 111.1)
        Token Y: 0 (10 - 10)

3 - User adds liquidity. Since the user wants 10 shares they must add they must add 10% (10/100) liquidity

    Pool 1
        Token X: 1222.2
        Token Y: 99
    Pool 2
        Token X: 1000
        Token Y: 121
    User
        Token X: 202 (111.1+90.9)
        Token Y: 20 (9 + 11)

4 - Attacker moves price back.

    Pool 1
        Token X: 1100
        Token Y: 110
    Pool 2
        Token X: 1100
        Token Y: 110
    Attacker
        Token X: 2 (-20.2 + 122.2 - 100)
        Token Y: 0 (11 - 11)

The min max formula is intended to account for changes in the underlying pools with the assumption that if the user is charge more of 1 token they are charged less of the other. Here we can see that by sandwiching the underlying pools this is invalidated and the user is charged more of one token while still paying the full amount of the other. 

## Impact

Slippage protections do not work for vaults with positions in more than one fee tier

## Code Snippet

[ArrakisV2Router.sol#L50-L119](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#L50-L119)

## Tool used

Manual Review

## Recommendation

To prevent this type of attack I would recommend using adding an invariant slippage check, which is the product of the amounts.

        require(
            amount0 >= params_.amount0Min &&
                amount1 >= params_.amount1Min &&
    +           amount1 * amount0 <= params_.amount1Min * params_.amount0Min &&
                sharesReceived >= params_.amountSharesMin,
            "below min amounts"
        );