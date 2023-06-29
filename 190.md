Tricko

high

# Attacker can steal trading fees by doing a flashloan, minting high amount of shares and burning at the same transaction.

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
