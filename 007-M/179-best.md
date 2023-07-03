0x52

medium

# ArrakisStorageV2#initialize allows whitelisting token0 and token1 as routers

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