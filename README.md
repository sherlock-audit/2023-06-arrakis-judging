# Issue H-1: Then getAmountsForDelta function at Underlying.sol is implemented incorrectly 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/8 

## Found by 
0xGoodess, 0xRobocop, elephant\_coral, levi, rogue-lion-0619
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



## Discussion

**Gevarist**

We consider this issue as a medium severity issue, because the cost of an attacker to benefit from this vulnerability and steal some token1 as expensive. The attacker needs to provide the equivalent amount of token0.

**ctf-sec**

The calculated amount to supply the token mismatched the actually supplied amount depends on the ticker range and the over-charged part from user fund is lost, recommend maintaining the high severity.

# Issue H-2: Lack of rebalance rate limiting allow operators to drain vaults 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/25 

## Found by 
cergyk, immeas, n33k, p12473
## Summary
Operators of Arrakis vaults are constrained by the checks defined in `SimpleManager.sol`, these checks prevent them from causing too much of a fund loss on a single rebalance call (check univ3 pool price deviation, enforce minimum swap slippage parameters). 

However since there is no rate limiting for an operator to call rebalance on SimpleManager, an operator can simply drain the vault by applying the accepted slippage a hundred times in one transaction.

## Vulnerability Detail
There are mostly two safety measures for preventing an operator to extract vault funds when calling rebalance:

- Check pool price deviation for mints:
    By checking that a pool price is close to a price given by a chainlink feed, operator is prevented from adding liquidity to a pool at a really unfavorable price, and backrun later to extract vault funds

- Check slippage parameters for swap (`_checkMinReturn`):
    By checking that a minimum amount of tokens is returned to the vault after the swap, it is preventing the operator to swap tokens at a too unfavorable price.
    Min amount out enforced in ArrakisV2:

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L341-L363

As stated by the sponsor, in a public trustless setup, these slippage parameters should be restricted to ~1%.

However since an operator is not rate limited for the number of calls she can do on `SimpleManager.rebalance`, she can simply call it multiple times in a very short timespan, extract an arbitrarily large share of vault funds.

## Impact
Vault funds can be drained by a malicious operator.

## Code Snippet

## Tool used

Manual Review

## Recommendation
Enforce a rate limiting policy to the number of calls which can be made to SimpleManager's rebalance, or even better enforce a rate limit on loss of funds which can occur due to rebalances (by evaluating `totalUnderlyingWithFees` before and after the execution for example).



## Discussion

**ctf-sec**

> Operators are "semi trusted" only to be awake and adhere to the expected vault rebalancing strategy. Thus a malicious operator on the SimpleManager.sol should not be able to do anything worse than "grief" - they MAY not execute rebalances or MAY not execute the expected strategy. However the rebalances that are executed MUST NOT be exploitable by frontrun or sandwich.

Based the info from the contest readme doc, upgrading the severity to high

# Issue H-3: ArrakisV2Router#addLiquidityPermit2 will strand ETH 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/183 

## Found by 
0x007, 0x52, 0xpinky, BenRai, DadeKuma, Jeiwan, auditor0517, auditsea, branch\_indigo, elephant\_coral, immeas, kutugu, rvierdiiev, tallo
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



## Discussion

**Gevarist**

We consider the issue as a medium issue, some user fund can be lost. Only the stranded eth can be potentially stolen.

**ctf-sec**

The finding result in lose of fund, recommend maintaining high severity.

# Issue M-1: Pool deviation check in SimpleManager on rebalance can be bypassed 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/26 

## Found by 
BenRai, YakuzaKiawe, cergyk, rugpull\_detector
## Summary
In `SimpleManager` a price deviation check is enforced to prevent an operator to add liquidity to a UniV3 pool at a really unfavorable price during rebalance and backrun to extract vault funds. We will show here that this check can be entirely bypassed by a malicious operator.

## Vulnerability Detail

### Rebalance context
During a call to `SimpleManger.rebalance`, the following operations are run:
- 1/ Enforce price deviation not too large for mint pools:
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/contracts/SimpleManager.sol#L366-L385

and correct slippage parameter for swap:
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/contracts/SimpleManager.sol#L318-L354

- 2/ Remove liquidity on specified UniV3 ranges (we are not going to use it here)

- 3/ Use a low level call to a whitelisted Router to execute a swap
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L334-L336

- 4/ Enforce received amounts from the swap 

- 5/ Provide liquidity on specified UniV3 ranges
- 6/ Enforce provided amounts during addLiquidity (these parameters are provided by operator and unbounded, so they can be (0, 0), and check is a noop). 

### Exploit description
We are going to use the swap step (3/) to imbalance the pools after the check of price deviation (1/) is passed, so the liquidity provided in 5/ is done at a really unfavorable price, and can be backrun by the operator to extract funds from the vault.

To not trigger the slippage protection after the swap, we are going to use the router to swap on a totally unrelated pool of tokens controlled by the malicious operator: `PSN/PSN2` (PSN stands for Poison).

`PSN` token has a callback in the `_transfer` function to make a large swap on UNIv3 pool where the operator is going to provide liquidity in 5/, to deviate it a lot.

after the call to the router is done, no changes to the balances of the vault have been made, the slippage checks out.

Liquidity provided at 5/ is done at a terrible price for some of the ranges, and the operator backruns for a nice profit. 

NB: All these steps can be run inside a flashloan callback, to not use attacker own funds

## Impact
An arbitrary amount can be drained from the vault by an operator

## Code Snippet

## Tool used
Manual Review

## Recommendation
Ideally the check on price deviation should be enforced right before the liquidity providing. 

# Issue M-2: The `ArrakisV2Router` pause feature can be bypassed calling directly the vault `mint()` `burn()` functions 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/33 

## Found by 
0xbepresent, 0xpinky, BenRai, branch\_indigo, cergyk, chainNue, elephant\_coral, flacko, rvierdiiev
## Summary

The `ArrakisV2Router` have the [pause()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/abstract/ArrakisV2RouterStorage.sol#L78)/[unpause()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/abstract/ArrakisV2RouterStorage.sol#L82) functions which help to put in pause/unpause mode the [ArrakisV2Router.addLiquidity()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#L53), [swapAndAddLiquidity()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#LL129C14-L129C33), [removeLiquidity()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#LL201C14-L201C29), [addLiquidityPermit2](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#LL238C14-L238C33), [swapAndAddLiquidityPermit2()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#LL309C14-L309C40), [removeLiquidityPermit2()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#LL357C14-L357C36), functions.

If the `Router` is in pause mode the add liquidity or remove liquidity in the `Vault` should not be possible but the pause mode can be bypassed calling directly to the vault `mint()`/`burn()` functions.

## Vulnerability Detail

The `Router` can be in paused mode via the [pause()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/abstract/ArrakisV2StaticManagerStorage.sol#L48) function but user can call directly to the `mint()`/`burn()` functions bypassing the pause feature.

I created a test where the Router owner pauses the contract and the `removeLiquidity()` function will be reverted, then the user can still call `burn()` function and receive the token0 and token1 bypassing the `removeLiquidity()` function. Test steps:

1) The owner pauses the router contract
2) The removeLiquidity() function is reverted by "Pausable: paused" error
3) The user call directly the burn() function successfully
4) The user receives his tokens
5) The user bypasses the `removeLiquidity()` function

```javascript
// $ yarn test --grep "ArrakisV2Router tests on USDC/WETH vault" --bail
// File: v2-periphery/test/ArrakisV2RouterUsdcWeth.test.ts
  it("0xbepresent_01_arrakisv2router : removeLiquidity from the vault even when the router is paused", async function () {
    //
    // 1) The owner pause the router contract
    // 2) The removeLiquidity() function is reverted by "Pausable: paused" error
    // 3) The user call directly the burn() function successfully
    // 4) The user receives his tokens
    const balanceArrakisV2Before = await rakisToken.balanceOf(walletAddress);
    expect(balanceArrakisV2Before).to.be.gt(ethers.constants.Zero);

    const balance0Before = await token0.balanceOf(walletAddress);
    const balance1Before = await token1.balanceOf(walletAddress);

    await rakisToken.approve(router.address, balanceArrakisV2Before);

    const removeLiquidity = {
      vault: vault.address,
      burnAmount: balanceArrakisV2Before.div(2),
      amount0Min: 0,
      amount1Min: 0,
      receiver: walletAddress,
      receiveETH: false,
      gauge: ethers.constants.AddressZero,
    };
    //
    // 1) The owner pause the router contract
    //
    await router.connect(owner).pause();
    //
    // 2) The removeLiquidity() function is reverted by "Pausable: paused" error
    //
    await expect(router.removeLiquidity(removeLiquidity)).to.be.revertedWith("Pausable: paused");
    //
    // 3) The user call directly the burn() function successfully
    //
    vault.burn(balanceArrakisV2Before.div(2), walletAddress);
    //
    // 4) The user receives his tokens
    //
    const balance0After = await token0.balanceOf(walletAddress);
    const balance1After = await token1.balanceOf(walletAddress);
    const balanceArrakisV2After = await rakisToken.balanceOf(walletAddress);

    expect(balance0After).to.be.gt(balance0Before);
    expect(balance1After).to.be.gt(balance1Before);
    expect(balanceArrakisV2Before).to.be.gt(balanceArrakisV2After);

    // UnPause the removeLiquidity in the router contract
    await router.connect(owner).unpause();
  });
```

## Impact

The vaults could be paused because there could be a problem in the vaults so all `mint()`/`burn()` transactions should be paused. E.g. a vault is compromised and the burn() function should be paused for everyone until there is a fix but the attacker can directly call the `burn()` function bypassing the pause mode.

Additionally, the [mint()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L54) function has a `restrictedMint` validation, so only the router can call this function, but since anyone can create a vault via [ArrakisV2Factory.sol](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2Factory.sol) it is possible to some vaults that it does not have the [restrictedMint](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2Storage.sol#L227) to the `ArrakisV2Router` address.

## Code Snippet

As you can see in the [burn()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L162) function, there is not any validation that the `burning` should not be possible if there is a pause in the `router` contract OR if the function is called by the `router`. It is totally open to everyone.

```solidity
File: ArrakisV2.sol
162:     function burn(uint256 burnAmount_, address receiver_)
163:         external
164:         nonReentrant
165:         returns (uint256 amount0, uint256 amount1)
166:     {
167:         require(burnAmount_ > 0, "BA");
168: 
169:         uint256 ts = totalSupply();
170:         require(ts > 0, "TS");
171: 
172:         _burn(msg.sender, burnAmount_);
173: 
174:         Withdraw memory total;
```

In the other hand, the [mint()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L54) function has the `restrictedMint` validation, but if the Vault has not settting up the `restrictedMint`, the `mint()` function can be called by everyone even when the router is paused.

```solidity
File: ArrakisV2.sol
54:     function mint(uint256 mintAmount_, address receiver_)
55:         external
56:         nonReentrant
57:         returns (uint256 amount0, uint256 amount1)
58:     {
59:         require(mintAmount_ > 0, "MA");
60:         require(
61:             restrictedMint == address(0) || msg.sender == restrictedMint,
62:             "R"
63:         );
64:         address me = address(this);
65:         uint256 ts = totalSupply();
```


## Tool used

Manual review

## Recommendation

The [mint()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L54) and [burn()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L162) should have the pause/unpause feature directly otherwise the [ArrakisV2Router.pause()/ArrakisV2Router.unpause()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/abstract/ArrakisV2RouterStorage.sol#L78-L84) functions are useless because it is possible to add liquidity and remove liquidity to the vaults directly via `mint()`/`burn()` functions.



## Discussion

**Gevarist**

The router can be paused if we find out that the router is compromised or buggy. It's the wanted behavior. 

**ctf-sec**

Emm Recommend leave as a medium severity

# Issue M-3: Rebalance may revert when sqrtPriceX96 > uint128 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/34 

## Found by 
GimelSec, carrotsmuggler, cergyk
## Summary
The squaring of the variable sqrtPriceX96 may revert if it is large due to integer overflow, and prevent rebalancing of the vault.

## Vulnerability Detail
As can be seen here, FullMath library is used to make calculations on 512 bits numbers:
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/contracts/SimpleManager.sol#L184

However the first argument: `sqrtPriceX96 * sqrtPriceX96` is of type uint256 and can cause an overflow if 
`sqrtPriceX96 >= 2**128`

Please note that this has been reported during a previous audit:
https://gist.github.com/kassandraoftroy/25f7208adb770abee9f46978326cfb3f (1st issue)

But has incorrectly been marked as fixed when it was not, so it seems that this should be counted as a valid issue in the scope of this contest,
since without it, it would have stayed unnoticed.

## Impact
Rebalance may be impossible to execute when sqrtPriceX96 is large (gte than 2**128)

## Code Snippet

## Tool used

Manual Review

## Recommendation
```solidity
uint256 poolPrice = 
    FullMath.mulDiv(
        FullMath.mulDiv(
            sqrtPriceX96,
            10 ** token0Decimals,
            2 ** 192
        ), 
        sqrtPriceX96, 
        1
    );
```
or similar



## Discussion

**Gevarist**

This vulnerability is not introducing user fund loss, so we are not considering this bug as a medium level issue.

**ctf-sec**

Recommend maintaining medium severity, the rebalance are not expected to revert and the case sqrtPriceX96 > uint128 should be properly handled

# Issue M-4: Using `slot0` to determine deviation is not ideal 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/71 

## Found by 
0x007, 0xbepresent, 0xhacksmithh, Bauchibred, immeas, levi, lil.eth, okolicodes, oot2k, radev\_sw, tsvetanovv

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



## Discussion

**Gevarist**

How DoS attack can be profitable to the attacker? By comparing current price of the pool against oracle price, we can be sure that the pool price is in an acceptable range. TWAP can be manipulated to go through the deviation check, and having in the same time a current pool price outside of the acceptable range.

**ctf-sec**

This report and all duplicate actually does not show the impact besides saying using slot0 can be manipulated, downgrade to medium for now

# Issue M-5: outdated variable is not effective to check price feed timeliness 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/83 

## Found by 
0x007, 0x52, 0xg0, BenRai, Jeiwan, ast3ros, cergyk, elephant\_coral, rvierdiiev, vnavascues
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



## Discussion

**Gevarist**

oracle price check will always revert for few specific feeds. Should not result in fund loss, we are not considering the issue as medium level.

**ctf-sec**

I think this regular revert impact the rebalance... 

#249 describes the issue well as well

recommend maintaining severity level

# Issue M-6: No slippage protection when adding liquidity to UniswapV3 pool 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/84 

## Found by 
0x007, 0x52, 0xDjango, Bauchibred, DadeKuma, ast3ros, cergyk, chainNue, dacian, n33k, tsvetanovv
## Summary

In ArrakisV2 vault, when minting Arrakis V2 shares, the underlying assets are deposited to UniswapV3 pool to provide liquidity. However, there is no slippage protection.

## Vulnerability Detail

If the total supply is more than 0, the deposited underlying assets are used to provide liquidity to UniswapV3 pool:

        pool.mint(me, range.lowerTick, range.upperTick, liquidity, "");

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L149

However, there are no parameters for `minDeposit0` and `minDeposit1`, which are used to prevent slippage. The function without slippage protection could be vulnerable to a front-running attack designed to execute the mint call at an unfavorable price.
 
For details of slippage protection when minting, please see:

https://docs.uniswap.org/contracts/v3/guides/providing-liquidity/mint-a-position#calling-mint
https://uniswapv3book.com/docs/milestone_3/slippage-protection/#slippage-protection-in-minting

## Impact

The function is exposed to front-running risk and could mint at a distorted price.

## Code Snippet

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L149

## Tool used

Manual Review

## Recommendation

Estimate the `minDeposit0` and `minDeposit1` like the mint part in the rebalance function. Revert if the total amount of token0 and token1 used is less than the minDeposit0 and minDeposit1.



## Discussion

**Gevarist**

amountSharesMin of ArrakisV2Router should protect new LPs to get less than what they initially wanted.

**ctf-sec**

Changing severity to medium for now

It is true the user can specify the amountSharesMin

and the amountSharesMin check logic is [here](https://github.com/sherlock-audit/2023-06-arrakis/blob/9594cf930307ebbfe5cae4f8ad9e9b40b26c9fec/v2-periphery/contracts/ArrakisV2Router.sol#L82)

```solidity
   (amount0, amount1, sharesReceived) = resolver.getMintAmounts(
            IArrakisV2(params_.vault),
            params_.amount0Max,
            params_.amount1Max
        );

        require(sharesReceived > 0, "nothing to mint");
        require(
            amount0 >= params_.amount0Min &&
                amount1 >= params_.amount1Min &&
                sharesReceived >= params_.amountSharesMin,
            "below min amounts"
        );
```

but the code never validate the amountSharesMin is at least the user received after the Pool.mint,

The auditor are welcome to escalate with more sound reason to make it as a high severity

# Issue M-7: ArrakisV2Router.addLiquidity needs deadline protection 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/99 

## Found by 
0xhacksmithh, DadeKuma, IceBear, MohammedRizwan, PRAISE, kutugu, okolicodes, peanuts, rvierdiiev
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



## Discussion

**Gevarist**

Transaction can be mined with delay when user uses very low priority fee. What can be the benefit of delaying the transaction, how that will penalize the user. By providing very low priority fee, user may want to have delayed execution.

**ctf-sec**

Think auditor means if the transaction is pending so long in the mempool, the slippage protection setting is oudated, recommend maintaing medium severity

**hrishibhat**

@Gevarist 

# Issue M-8: Uniswap oracle should not be used on L2s 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/111 

## Found by 
Bauchibred, rogue-lion-0619


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



## Discussion

**Gevarist**

Not in the scope

**ctf-sec**

Recommend change the severity to medium, TWAP price manipulation dose cause problem:

https://twitter.com/immunefi/status/1679269288375451649

# Issue M-9: Slippage protection for ArrakisV2Router#addLiquidity can be abused if the vault is active in more than one fee tier 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/164 

## Found by 
0x52, cergyk
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



## Discussion

**Gevarist**

amountSharesMin should protect us against this attack. Can the attacker manipulate the pools and in the same time fulfill amountSharesMin requirement?

**ctf-sec**

Maintaining the medium severity based on the info from #28 

# Issue M-10: ArrakisStorageV2#initialize allows whitelisting token0 and token1 as routers 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/179 

## Found by 
0x52, 0xHati, lil.eth, rvierdiiev
## Summary

When initializing ArrakisV2Storage the _whitelistRouters subcall takes place before token0 and token1 are set allowing them to be added as routers. This allows honeypotting users since the calls to those contracts can be used to drain both the contents of the contract and anyone to has an allowance to the vault (which is why they are blocked to begin with).

## Vulnerability Detail

[ArrakisV2Storage.sol#L134-L137](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2Storage.sol#L134-L137)

        _whitelistRouters(params_.routers);

        token0 = IERC20(params_.token0);
        token1 = IERC20(params_.token1);

Here we see in the initialize that _whitelistRouters is called before token0 and token1 are set.

[ArrakisV2Storage.sol#L311-L324](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2Storage.sol#L311-L324)

    function _whitelistRouters(address[] calldata routers_) internal {
        for (uint256 i = 0; i < routers_.length; i++) {
            require(
                routers_[i] != address(token0) &&
                    routers_[i] != address(token1),
                "RT"
            );
            require(!_routers.contains(routers_[i]), "CR");
            // explicit.
            _routers.add(routers_[i]);
        }
        emit LogWhitelistRouters(routers_);
    } 

Above we see that token0 and token1 are checked to block whitelisting the tokens are routers (which can receive calls directly). The problem is that since token0 and token1 are not set yet, the token addresses are fully valid. This allows keepers to directly steal funds from anyone that has created an allowance to the vault contract. As stated in the readme, keepers are only semi-trusted and should only be able to grief the vault. This is a clear violation of that. 

## Impact

Keepers can steal funds from any user with an allowance to the vault

## Code Snippet

[ArrakisV2Storage.sol#L118-L149](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2Storage.sol#L118-L149)

## Tool used

Manual Review

## Recommendation

Change the order of the calls:

    -   _whitelistRouters(params_.routers);

        token0 = IERC20(params_.token0);
        token1 = IERC20(params_.token1);

    +   _whitelistRouters(params_.routers);

        _transferOwnership(params_.owner);

# Issue M-11: SimpleManager#rebalance fails to check if burned pools are unbalanced 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/181 

## Found by 
0x52
## Summary

SimpleManager checks that all pools being minted to are balanced within a certain threshold. This prevents the contract from minting to unbalanced pools to protect it from sandwich attacks. The problem is that it doesn't check for pools that are burned from but not minted too. Burning unbalanced pools are just as damaging as minting to them which can lead to losses due to sandwich attacks. 

## Vulnerability Detail

[SimpleManager.sol#L157-L198](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/contracts/SimpleManager.sol#L157-L198)

        if (mintsLength > 0) {
            checked = new uint24[](mintsLength);
            oraclePrice = vaultInfo.oracle.getPrice0();
        }

        for (uint256 i; i < mintsLength; ++i) {

            ...

            _checkDeviation(
                poolPrice,
                oraclePrice,
                vaultInfo.maxDeviation,
                token1Decimals
            );

            checked[increment] = rebalanceParams_.mints[i].range.feeTier;
            increment++;
        }

In the code above the pool price of each minting pool is validated against the expected price from the oracle. This disallows minting to unbalanced pool. This check doesn't, however, account for pools that are being burned from. This allows those burns to be sandwich attacked.

## Impact

Pools that are burned from but not minted to can be sandwich attacked

## Code Snippet

[SimpleManager.sol#L128-L214](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-manager-templates/contracts/SimpleManager.sol#L128-L214)

## Tool used

Manual Review

## Recommendation

SimpleManager#rebalance should check pools burned from as well.

# Issue M-12: Attacker can steal trading fees by doing a flashloan, minting high amount of shares and burning at the same transaction. 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/190 

## Found by 
0xDjango, Tricko
## Summary
Due to the way leftover balance is distributed in the ArrakisV2 vault during `burn`, an attacker can steal most of the trading fees from the vault by doing a flashloan, minting high amount of shares and burning them at the same transaction.

## Vulnerability Detail
During the ArrakisV2 vault `burn` process, the amount of funds proportional to `burnAmount_` are burned from the various tick ranges and fees are collected. But due to the way UniswapV3 pools works, the fees collected are the total uncollected fees of that position, not only those proportional to `burnAmount_`. Therefore after `_withdraw` is called, the balance of the vault contract will be `(user share of burned LP + user share of fees + fees for all the other shareholders)`. To deal with that, the burn logic calculate the appropriate amount correspondings to the user's share from all the leftover balance in the vault, like shown below.

```solidity
// the proportion of user balance.
amount0 = FullMath.mulDiv(leftOver0, burnAmount_, ts);
amount1 = FullMath.mulDiv(leftOver1, burnAmount_, ts);
```

Time accounting is not a factor, meaning that regardless of whether the user has spent 200 days or only one block "inside" the vault, they are entitled to their share of the `leftOver` based solely on the number of shares they possess. So an attacker can exploit this by getting a flashloan, minting high amount of shares and then burning all of them at the same transaction. Because the attacker used the flashloan to get high amount of shares, he will get a proportionate high amount of fees during burn, effectively reducing all the other shareholders fees.

Consider the scenario below as an example. To simplify ignore manager fees.
combined uncollected fees from all ranges = 10e18
totalSupply = 1e22
1. Attacker gets flashloan
2. Attacker mints 9e22 shares
Attackers owns 90% of the totalSupply
3. Attacker burns 9e22 shares
Attacker recovers his funds used for minting (as he does everthing in one transaction, there is no risk) and gets 9e18 as profit (90% of the fees).
4. Attacker replays his flashloan 

## Impact
Attacker will get most of the vaults trading fees even without contributing to the vault, as he mints and burn in the same transaction, so his funds contribute nothing to the vault's trading fees. Other vault shareholders will be affected as they won't be able to withdrawn the fees they would be due without the attack.

## Code Snippet
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/ArrakisV2.sol#L162-L236

## Tool used
Manual Review

## Recommendation
Consider making it impossible for the same user to mint and burn at the same block. Also define a minimum wait time between mints and burns for any user.



## Discussion

**Gevarist**

Only mintAmount/totalSupply ratio of liquidities of uniswap v3 positions will be minted, mintAmount/totalSupply ratio of left over will be put in the vault + the minter will also put  mintAmount/(totalSupply) of fees previously generated as left over.

**ctf-sec**

Emmmm for this one, I will just downgrade to medium, the auditor needs to escalate with further sufficient proof to make a as high severity issue

# Issue M-13: Update to `managerFeeBPS` applied to pending tokens yet to be claimed 

Source: https://github.com/sherlock-audit/2023-06-arrakis-judging/issues/198 

## Found by 
0xDjango, Jeiwan, ast3ros, dipp, immeas, rugpull\_detector, rvierdiiev
## Summary
A manager (malicious or not) can update the `managerFeeBPS` by calling `ArrakisV2.setManagerFeeBPS()`. The newly-updated `managerFeeBPS` will be retroactively applied to the pending fees yet to be claimed by the `ArrakisV2` contract.

## Vulnerability Detail
Whenever UniV3 fees are collected (via `burn()` or `rebalance()`), the manager fees are applied to the received pending tokens.

```solidity
function _applyFees(uint256 fee0_, uint256 fee1_) internal {
    uint16 mManagerFeeBPS = managerFeeBPS;
    managerBalance0 += (fee0_ * mManagerFeeBPS) / hundredPercent;
    managerBalance1 += (fee1_ * mManagerFeeBPS) / hundredPercent;
}
```

Since the manager can update the `managerFeeBPS` whenever, this calculation can be altered to take up to 100% of the pending fees in favor of the manager.

```solidity
function setManagerFeeBPS(uint16 managerFeeBPS_) external onlyManager {
    require(managerFeeBPS_ <= 10000, "MFO");
    managerFeeBPS = managerFeeBPS_;
    emit LogSetManagerFeeBPS(managerFeeBPS_);
}
```

## Impact
- Manager's ability to intentionally or accidently steal pending fees owed to stakers

## Code Snippet
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2Storage.sol#L218-L222

## Tool used
Manual Review

## Recommendation
Fees should be collected at the start of execution within the `setManagerFeeBPS()` function. This effectively checkpoints the fees properly, prior to updating the `managerFeeBPS` variable.

