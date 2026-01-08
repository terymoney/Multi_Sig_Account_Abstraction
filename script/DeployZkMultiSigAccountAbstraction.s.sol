// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Script, console } from "forge-std/Script.sol";
import { ZkMultiSigAccountAbstraction } from "src/zkSync/ZkMultiSigAccountAbstraction.sol";

contract DeployZkMultiSigAccountAbstraction is Script {
    function run() public {
        vm.startBroadcast(vm.envUint("PRIVATE_KEY_1"));
        deploy();
        vm.stopBroadcast();
    }

    function deploy() public returns (ZkMultiSigAccountAbstraction) {
        uint256 owner1Key = vm.envUint("PRIVATE_KEY_1");
        uint256 owner2Key = vm.envUint("PRIVATE_KEY_2");

        address owner1 = vm.addr(owner1Key);
        address owner2 = vm.addr(owner2Key);

        address[] memory owners = new address[](2);
        owners[0] = owner1;
        owners[1] = owner2;

        ZkMultiSigAccountAbstraction account = new ZkMultiSigAccountAbstraction(owners);

        console.log("ZkMultiSigAccountAbstraction deployed at:", address(account));
        console.log("Owner 1:", owner1);
        console.log("Owner 2:", owner2);

        return account;
    }
}
