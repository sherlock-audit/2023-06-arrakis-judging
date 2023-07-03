branch_indigo

high

# Malicious users can bypass whitelisting control.

## Summary
Malicious users can bypass whitelisting control.
## Vulnerability Detail
A vault can be set up to only allow whitelisted users to mint and have their assets managed. This is implemented in `_addLiquidity()` in ArrakisV2Router.sol. 
```solidity
//ArrakisV2Router.sol-_addLiquidity()
...
            if (mintRules.hasWhitelist) {
                require(
>>>               _mintWhitelist[vault_].contains(msg.sender),
                    "not whitelisted"
                );
            }
...
```
A non-whitelisted user can directly mint liquidity through ArrakisV2.sol-mint(), where there is not check on whether msg.sender is whitelisted, nor there is a variable to hold whitelisted users. The malicious user can still implement all slippage control in a malicious contract.
```solidity
    function mint(
        uint256 mintAmount_,
        address receiver_
    ) external nonReentrant returns (uint256 amount0, uint256 amount1) {
        require(mintAmount_ > 0, "MA");
...
```

## Impact
A malicious user who is not white-listed can still mint in a restricted vault.
## Code Snippet
[https://github.com/ArrakisFinance/v2-periphery/blob/ee6d7c5f3ffb212887db4ec0e595618ea418070f/contracts/ArrakisV2Router.sol#L422-L424](https://github.com/ArrakisFinance/v2-periphery/blob/ee6d7c5f3ffb212887db4ec0e595618ea418070f/contracts/ArrakisV2Router.sol#L422-L424)
## Tool used

Manual Review

## Recommendation
Implement the white-listed user variable in the core ArrakisV2.sol instead.