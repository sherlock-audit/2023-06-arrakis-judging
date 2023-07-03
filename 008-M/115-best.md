branch_indigo

high

# Malicious users can easily bypass supply cap

## Summary
Malicious users can easily bypass supply cap.
## Vulnerability Detail
When a user add liquidity through ArrakisV2Router.sol. The vault supply cap is checked in `_addLiquidity()`, which check minting rules in mapping variable `mintRestrictedVaultes` from ArrakisV2RouterStorage.sol.
```solidity
//ArrakisV2Router.sol - _addLiquidity()
...
            MintRules memory mintRules = mintRestrictedVaults[vault_];
            if (mintRules.supplyCap > 0) {
                require(
>>>                 IArrakisV2(vault_).totalSupply() + mintAmount_ <=
                        mintRules.supplyCap,
                    "above supply cap"
                );
            }
...
```
But this require statement can be easily bypassed by a malicious actor who interacts directly with ArrakisV2.sol `mint()`, where no vault specific minting rules are stored, and neither is a cap of `totalSupply()` checked.
```solidity
//ArrakisV2.sol
    function mint(
        uint256 mintAmount_,
        address receiver_
    ) external nonReentrant returns (uint256 amount0, uint256 amount1) {
        require(mintAmount_ > 0, "MA");
...
```

## Impact
A malicious user can easily bypass a vault supply cap, putting the vault's health at risk.
## Code Snippet
[https://github.com/ArrakisFinance/v2-periphery/blob/ee6d7c5f3ffb212887db4ec0e595618ea418070f/contracts/ArrakisV2Router.sol#L415-L418](https://github.com/ArrakisFinance/v2-periphery/blob/ee6d7c5f3ffb212887db4ec0e595618ea418070f/contracts/ArrakisV2Router.sol#L415-L418)
## Tool used

Manual Review

## Recommendation
Allow the owner to set `supplyCap` directly on ArrakisV2.sol. And enforce supplyCap check in `mint()`.