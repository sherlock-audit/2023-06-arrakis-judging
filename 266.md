0xDjango

high

# Malicious vault owner can steal value from first mint()

## Summary
Upon first mint (totalSupply = 0), the price of minting Arrakis pool tokens is determined based on the `init0` and `init1` storage variables. The first `mint()` call can be frontrun by a malicious vault owner who can set these variables to much higher values, resulting in large quantities of tokens pulled from the minting user.

## Vulnerability Detail
The amount of token0 and token1 needed for the first mint is calculated by:

```solidity
        if (isTotalSupplyGtZero) {
            ...
        } else {
            uint256 denominator = 1 ether;
            uint256 init0M = init0;
            uint256 init1M = init1;


            amount0 = FullMath.mulDivRoundingUp(
                mintAmount_,
                init0M,
                denominator
            );
            amount1 = FullMath.mulDivRoundingUp(
                mintAmount_,
                init1M,
                denominator
            );


            /// @dev check ratio against small values that skew init ratio
            if (FullMath.mulDiv(mintAmount_, init0M, denominator) == 0) {
                amount0 = 0;
            }
            if (FullMath.mulDiv(mintAmount_, init1M, denominator) == 0) {
                amount1 = 0;
            }
```

`init0` and `init1` are multipliers that determine the amount of token0 and token1 needed to mint the desired `mintAmount_` of Arrakis pool tokens.

The malicious vault owner can frontrun this mint call and update the `init0` and `init1` variable by calling `ArrakisV2.setInits()`:

```solidity
    function setInits(uint256 init0_, uint256 init1_) external {
        require(init0_ > 0 || init1_ > 0, "I");
        require(totalSupply() == 0, "TS");
        address requiredCaller = restrictedMint == address(0)
            ? owner()
            : restrictedMint;
        require(msg.sender == requiredCaller, "R");
        emit LogSetInits(init0 = init0_, init1 = init1_);
    }
```

The newly-increased variable values will result in more token0 and token1 pulled from the user.

***The opposite issue is also a problem. The malicious vault owner can frontrun a `mint()` call by setting the `init0` and `init1` value to `1 wei` and mint themselves unlimited pool tokens for free. Now they can transfer some funds to the contract. The original naive minter will mint some tokens, but the owner has a disproportionately huge amount of pool tokens to burn and steal funds.***

## Impact
- More token0 and token1 pulled from minter than desired.

## Code Snippet
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2Storage.sol#L157-L165

## Tool used
Manual Review

## Recommendation
Remove the `setInits()` function. These values are set in the initializer and should not be able to be modified.
