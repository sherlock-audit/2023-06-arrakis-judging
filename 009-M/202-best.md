0xDjango

medium

# Arbitrary SwapRouters can grant themselves hanging allowances

## Summary
The `ArrakisV2Router` allows a user to perform a swap and add liquidity in a single function call. The user supplies arbitrary `SwapData`, which includes a `swapRouter` address and arbitrary bytes `swapPayload`. This data is sent to the `RouterSwapExecutor` contract which performs the swap based on the input data.

The `RouterSwapExecutor` is careful to clear all allowances after the swap has taken place. However, allowances can easily be created by a malicious caller and they can not be cleared. If the caller provides a **token contract** for the `swapRouter` and an `approve()` call for the `swapPayload`, the allowance will remain after function execution.

## Vulnerability Detail
The relevant portion of `RouterSwapExecutor.swap()` is as follows:

```solidity
    function swap(SwapAndAddData memory swapAndAddData_)
        external
        onlyRouter
        returns (uint256 amount0Diff, uint256 amount1Diff)
    {
        IERC20 token0 = IArrakisV2(swapAndAddData_.addData.vault).token0();
        IERC20 token1 = IArrakisV2(swapAndAddData_.addData.vault).token1();
        uint256 balanceBefore;
        if (swapAndAddData_.swapData.zeroForOne) {
            balanceBefore = token0.balanceOf(address(this));
            token0.safeIncreaseAllowance(
                swapAndAddData_.swapData.swapRouter,
                swapAndAddData_.swapData.amountInSwap
            );
        } else {
            balanceBefore = token1.balanceOf(address(this));
            token1.safeIncreaseAllowance(
                swapAndAddData_.swapData.swapRouter,
                swapAndAddData_.swapData.amountInSwap
            );
        }
        (bool success, ) = swapAndAddData_.swapData.swapRouter.call(
            swapAndAddData_.swapData.swapPayload
        );
        require(success, "swap: low-level call failed");


        // setting allowance to 0
        if (swapAndAddData_.swapData.zeroForOne) {
            token0.safeApprove(swapAndAddData_.swapData.swapRouter, 0);
        } else {
            token1.safeApprove(swapAndAddData_.swapData.swapRouter, 0);
        }
```

Take the following example:
- `token0` = **USDC**
- `token1` = **WETH**
- `swapAndAddData_.swapData.swapRouter` = **WETH Contract**
- `swapAndAddData_.swapData.zeroForOne` = **true**. Therefore, the **WETH Contract** is approved to spend the **USDC**.
- The following call will set infinite approval on the WETH contract:
`(bool success, ) = swapAndAddData_.swapData.swapRouter.call(
            swapAndAddData_.swapData.swapPayload
        );`
AKA
`(bool success, ) = WETH.call(
            approve(maliciousSpender, uint(-1)
        );`

- Later in the execution, the USDC approval is cleared.
- The WETH approval remains.

## Impact
- Infinite hanging approvals despite careful checks to clear approvals.

## Code Snippet
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-periphery/contracts/RouterSwapExecutor.sol#L57-L59

## Tool used
Manual Review

## Recommendation
Consider creating a swapRouter whitelist instead of allowing an arbitrary address. The arbitrary address can be a token contract itself.
