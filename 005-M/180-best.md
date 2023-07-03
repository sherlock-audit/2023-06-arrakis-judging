0x52

medium

# Manager blacklisted by underlying vault token can permanently DOS rebalances on the vault

## Summary

If the manager of the vault becomes blacklisted by an underlying token of the vault, they can't be removed by the owner due to their fees being withdrawn to them. Since they cannot be replaced, rebalances will cease to function as only they can call it.

## Vulnerability Detail

[ArrakisV2Storage.sol#L209-L213](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2Storage.sol#L209-L213)

    function setManager(address manager_) external onlyOwner {
        _withdrawManagerBalance();
        manager = manager_;
        emit LogSetManager(manager_);
    }

When a new manager is set, the manager balance is withdrawn to them. This attempts to send the fees directly to the manager. However if the manager is blacklisted on and underlying token (such as USDC) then this call will always revert. This makes it impossible to change the manager of the contract leading to rebalances being DOS'd.

## Impact

Rebalances are DOS'd

## Code Snippet

[ArrakisV2Storage.sol#L209-L213](https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2Storage.sol#L209-L213)

## Tool used

Manual Review

## Recommendation

Instead of paying out fees when managers are changed, cache the fees in a mapping and allow the former manager to claim them there.