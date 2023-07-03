lil.eth

medium

# Initialization Order Vulnerability in initialize() Function

## Summary
Any address, including those of token0 and token1, can be added to the routers array when initializing even if there are designed remediations to prevent this, then it is a way for owner or operator to extract direct value from `rebalance()` function 

## Vulnerability Detail

Regarding the vulnerability **[WP‐H1] Dangerous arbitrary external call can be used by the manager to steal funds from the users who have approved tokens to the vault contract** in your old report where the recommendations were **Consider blacklist token0 and token1 as` _swapData.swapRouter`** the workaround is not working as token0 and token1 can still be added as a router.

The `_whitelistRouters()` function is called within `initialize()` before the token0 and token1 addresses are set. The `_whitelistRouters()` function includes a require statement that checks whether the addresses provided in routers_ are not equal to `token0` or `token1`. However, since these token addresses are not yet set at the time `_whitelistRouters()` is first called, they are still the  address(0) then the require statement does not effectively prevent the addresses of token0 and token1 from being added as routers.

Initialize function on ArrakisV2Storage.sol : 
```solidity
function initialize(
        string calldata name_,
        string calldata symbol_,
        InitializePayload calldata params_
    ) external initializer {
        ...
        //E ensure we need a router (more than 2 tokens),check that router address is not known and add it on _routers
        _whitelistRouters(params_.routers); //E @audit-issue token0 and token1 are not set
        //set addresses of tokens @audit-issue after calling _whitelistRouters
        token0 = IERC20(params_.token0);
        token1 = IERC20(params_.token1);
        ...
    }
```
whitelistRouters function that check if routers_ does not contain token0 or token1 but these address are not initialized yet : 
```solidity
    function _whitelistRouters(address[] calldata routers_) internal {
        for (uint256 i = 0; i < routers_.length; i++) {
            require(
                routers_[i] != address(token0) &&
                    routers_[i] != address(token1),
                "RT"
            );
           ....
        }
    }
```
Rebalance function that check if rebalanceParams_.swap.router is "whitelisted" and execute swaps needed to rebalance : 
```solidity
require(_routers.contains(rebalanceParams_.swap.router), "NR"); 
(bool success, ) = rebalanceParams_.swap.router.call(
                rebalanceParams_.swap.payload //E bytes payload prepared offChain
            );
```


## Impact

For the users who approved the vault contract to directly without using the router, `manager` can rebalance with token0 or token1's address as `RebalanceParams_.swap.router` and `transferFrom(victim,attacker,amount)` as payload to steal funds from the victim.
Besides, the manager can also use `transfer(attacker,amount)` as the payload and sweep the amounts in the balance to rug all users.
As it is an "owner" vulnerability I submit it as a Medium, can be downgraded or upgraded but need to be remediated to prevent this to happen.
As quoted in Readme : "there should be no way to extract value from these rebalances directly beyond the acceptable slippage tolerance defined in SimpleManager" => it is a way to extract value from these rebalances beyond the acceptable slipper tolerance so I think it is at least a valid medium finding.

## Code Snippet

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2Storage.sol#L118-L150 => initialize() function

https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2Storage.sol#L311-L324 => _whitelisRouters() function : 
```solidity
   function _whitelistRouters(address[] calldata routers_) internal {
        for (uint256 i = 0; i < routers_.length; i++) {
            require( //E @audit-issue token0 and token1 not defined for initialize() call
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
```
## Tool used

Manual Review

## Recommendation
Change the order of execution in the initialize() function to set token0 and token1 before the call to _whitelistRouters(). This will ensure the require statement in _whitelistRouters() functions as intended by preventing the token0 and token1 addresses from being added as routers.

Adjusted code:
```solidity
token0 = IERC20(params_.token0);
token1 = IERC20(params_.token1);
_whitelistRouters(params_.routers);
```

With this change, the addresses of token0 and token1 are correctly set before the call to _whitelistRouters(), ensuring that the function behaves as expected.