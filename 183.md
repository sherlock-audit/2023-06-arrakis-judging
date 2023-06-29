0x52

high

# ArrakisV2Router#addLiquidityPermit2 will strand ETH

## Summary

Inside ArrakisV2Router#addLiquidityPermit2, `isToken0Weth` is set incorrectly leading to the wrong amount of ETH being refunded to the user

## Vulnerability Detail

[ArrakisV2Router.sol#L278-L298](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#L278-L298)

        bool isToken0Weth;
        _permit2Add(params_, amount0, amount1, token0, token1);

        _addLiquidity(
            params_.addData.vault,
            amount0,
            amount1,
            sharesReceived,
            params_.addData.gauge,
            params_.addData.receiver,
            token0,
            token1
        );

        if (msg.value > 0) {
            if (isToken0Weth && msg.value > amount0) {
                payable(msg.sender).sendValue(msg.value - amount0);
            } else if (!isToken0Weth && msg.value > amount1) {
                payable(msg.sender).sendValue(msg.value - amount1);
            }
        }

Above we see that excess msg.value is returned to the user at the end of the function. This uses the value of isToken0Weth to determine the amount to send back to the user. The issue is that `isToken0Weth` is set incorrectly and will lead to ETH being stranded in the contract. `isToken0Weth` is never set, it will always be `false`. This means that when WETH actually is token0 the incorrect amount of ETH will be sent back to the user. 

This same issue can also be used to steal the ETH left in the contract by a malicious user. To make matters worse, the attacker can manipulate the underlying pools to increase the amount of ETH left in the contract so they can steal even more.

## Impact

ETH will be stranded in contract and stolen

## Code Snippet

[ArrakisV2Router.sol#L238-L299](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#L238-L299)

## Tool used

Manual Review

## Recommendation

Move `isToken0Weth` and set it correctly:

    -   bool isToken0Weth;
        _permit2Add(params_, amount0, amount1, token0, token1);

        _addLiquidity(
            params_.addData.vault,
            amount0,
            amount1,
            sharesReceived,
            params_.addData.gauge,
            params_.addData.receiver,
            token0,
            token1
        );

        if (msg.value > 0) {
    +       bool isToken0Weth = _isToken0Weth(address(token0), address(token1));
            if (isToken0Weth && msg.value > amount0) {
                payable(msg.sender).sendValue(msg.value - amount0);
            } else if (!isToken0Weth && msg.value > amount1) {
                payable(msg.sender).sendValue(msg.value - amount1);
            }
        }