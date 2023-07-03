alexzoid

medium

# Batch upgrade fails with inclusion of a `BeaconProxy` vault in vault array

## Summary
The Vault Factory's administrative functions revert if there's at least one `BeaconProxy` vault among the list of passed addresses.

## Vulnerability Detail
Vault deployment can occur via `BeaconProxy` or `TransparentProxy`. For `BeaconProxy`, the implementation address is extracted from a `UpgradeableBeacon` contract, which eliminates the need for a direct implementation upgrade. On the other hand, `TransparentProxy` stores the implementation address within the proxy contract and requires a direct upgrade via the `TransparentProxy.upgradeTo()` function.

The `ArrakisV2Factory` interface functions `upgradeVaults()`, `upgradeToAndCall()`, and `makeVaultsImmutable()` are correctly implemented for the `TransparentProxy` vault, but fail for `BeaconProxy`. This is due to `BeaconProxy` contract's lack of implementing `upgradeTo()`, `upgradeToAndCall()`, and `changeAdmin()`. Moreover, `ArrakisV2Factory.getProxyAdmin()` and `ArrakisV2Factory.getProxyImplementation()` also revert when `BeaconProxy` vault is passed.

Thus, if an array of vault addresses includes even a single `BeaconProxy` vault, the entire transaction reverts. This scenario is plausible given the array of vault addresses is acquired via a slice with `ArrakisV2Factory.vaults(startIndex, endIndex)`.

## Impact
When a `BeaconProxy` vault is included in the list of addresses, the factory's administrative functions are blocked.

## Code Snippet
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2FactoryStorage.sol#L50
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2FactoryStorage.sol#L67-L69
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2FactoryStorage.sol#L79
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2FactoryStorage.sol#L93-L95
https://github.com/sherlock-audit/2023-06-arrakis/blob/main/v2-core/contracts/abstract/ArrakisV2FactoryStorage.sol#L110-L112

## Proof Of Concept
The Foundry PoC illustrates a potential scenario where the owner wants to upgrade or render all factory vaults immutable. The factory houses three vaults: one deployed as `TransparentProxy`, one as a `BeaconProxy`, and the last as a `TransparentProxy`. Upgrading this batch of vaults leads to transaction reversion.

Create a file `v2-core/test/foundry/ArrakisV2.t.sol` with the source code below.
```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.13;

import {ArrakisV2} from "../../contracts/ArrakisV2.sol";
import {ArrakisV2Factory} from "../../contracts/ArrakisV2Factory.sol";
import {ArrakisV2Beacon} from "../../contracts/ArrakisV2Beacon.sol";
import {ArrakisV2FactoryStorage} from "../../contracts/abstract/ArrakisV2FactoryStorage.sol";
import {IArrakisV2Beacon} from "../../contracts/interfaces/IArrakisV2Beacon.sol";
import {IUniswapV3Factory} from "../../contracts/abstract/ArrakisV2Storage.sol";
import {InitializePayload} from "../../contracts/structs/SArrakisV2.sol";

import "forge-std/Test.sol";
import "forge-std/Vm.sol";

import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

address constant usdc = 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174;
address constant weth = 0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619;
address constant uniFactory = 0x1F98431c8aD98523631AE4a59f267346ea31F984;
Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

contract TestWrapper is Test {
    constructor() {
        vm.createSelectFork(
            vm.envString("ETH_RPC_URL"),
            vm.envUint("BLOCK_NUMBER")
        );
    }
}

contract ArrakisV2Test is TestWrapper {

    address proxyAdmin;
    address factoryOwner;
    address beaconOwner;
    address vaultOwner;
    address vaultManager;

    ArrakisV2Factory arrakisV2Factory;

    function setUp() public {

        // Upgrade `ArrakisV2Factory`
        proxyAdmin = vm.addr(1);
        // Upgrade vaults from beacon
        factoryOwner = vm.addr(2);
        // Set vault implementation
        beaconOwner = vm.addr(3);
        // Own and manage vault
        vaultOwner = vm.addr(4);
        vaultManager = vm.addr(5);

        ArrakisV2 arrakisV2 = new ArrakisV2(IUniswapV3Factory(uniFactory));

        ArrakisV2Beacon arrakisV2Beacon = new ArrakisV2Beacon(address(arrakisV2), beaconOwner);

        ArrakisV2Factory _arrakisV2Factory = new ArrakisV2Factory(
            IArrakisV2Beacon(address(arrakisV2Beacon))
            );

        arrakisV2Factory = ArrakisV2Factory(
            payable(
                new TransparentUpgradeableProxy(
                    address(_arrakisV2Factory),
                    proxyAdmin,
                    abi.encodeWithSelector(
                        ArrakisV2FactoryStorage.initialize.selector,
                        factoryOwner
                    )
                )
            )
        );  

        uint24[] memory feeTiers = new uint24[](1);
        feeTiers[0] = 500;
        address token0 = address(usdc);
        address token1 = address(weth);
        address owner = vaultOwner;
        uint256 init0 = 1700_1000000;
        uint256 init1 = 1 ether;
        address manager = vaultManager;
        address[] memory routers;
        InitializePayload memory initializePayload = InitializePayload(
            feeTiers, 
            token0,
            token1,
            owner,
            init0,
            init1,
            manager,
            routers
        );

        ArrakisV2(arrakisV2Factory.deployVault(initializePayload, false));
        ArrakisV2(arrakisV2Factory.deployVault(initializePayload, true));
        ArrakisV2(arrakisV2Factory.deployVault(initializePayload, false));
    }

    function test_Revert_FactoryUpgradeVaults_BeaconProxy() public {
        
        // Upgrade beacon implemantation
        ArrakisV2 arrakisV2Upgraded = new ArrakisV2(IUniswapV3Factory(uniFactory));
        assert(beaconOwner == arrakisV2Factory.arrakisV2Beacon().owner());
        vm.startPrank(beaconOwner);
        arrakisV2Factory.arrakisV2Beacon().upgradeTo(address(arrakisV2Upgraded));
        assert(address(arrakisV2Upgraded) == arrakisV2Factory.arrakisV2Beacon().implementation());
        
        // Get all vaults 
        uint256 numVaults = arrakisV2Factory.numVaults();
        address[] memory addr = arrakisV2Factory.vaults(0, numVaults);

        changePrank(factoryOwner);
        /** 
        * `upgradeVaults()` and `upgradeVaultsAndCall` will always revert for `BeaconProxy` vaults existance
        * because `upgradeTo()` and `upgradeToAndCall()` methods are not supported
        */
        vm.expectRevert();
        arrakisV2Factory.upgradeVaults(addr);        
    }

    function test_Revert_FactoryMakeVaultsImmutable_BeaconProxy() public {
                
        // Get all vaults 
        uint256 numVaults = arrakisV2Factory.numVaults();
        address[] memory addr = arrakisV2Factory.vaults(0, numVaults);

        vm.startPrank(factoryOwner);
        /** 
        * `makeVaultsImmutable()` will always revert for `BeaconProxy` vaults existance
        * because `changeAdmin()` method is not supported
        */
        vm.expectRevert();
        arrakisV2Factory.makeVaultsImmutable(addr);
    }
}
```

Start a test with the command `forge test -vv` inside a `v2-core` directory. There is an example of output below:
```bash
[⠆] Compiling...
[⠑] Compiling 2 files with 0.8.13
[⠊] Solc 0.8.13 finished in 3.36s
Compiler run successful!

Running 2 tests for test/foundry/ArrakisV2.t.sol:ArrakisV2Test
[PASS] test_Revert_FactoryMakeVaultsImmutable_BeaconProxy() (gas: 60251)
[PASS] test_Revert_FactoryUpgradeVaults_BeaconProxy() (gas: 4568520)
Test result: ok. 2 passed; 0 failed; finished in 14.63s
```

## Tool used
VSCodium, Foundry

## Recommendation
I recommend storing each vault's type within the factory, and avoid calling `TransparentProxy` interface functions for `BeaconProxy` vaults.