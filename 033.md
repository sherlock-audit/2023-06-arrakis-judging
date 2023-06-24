0xbepresent

medium

# The `ArrakisV2Router` pause feature can be bypassed calling directly the vault `mint()` `burn()` functions

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
