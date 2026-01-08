// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Script, console2 } from "forge-std/Script.sol";
import { HelperConfig } from "./HelperConfig.s.sol";
import { MultiSigAccountAbstraction } from "src/ethereum/MultiSigAccountAbstraction.sol";

contract DeployMultiSigAccountAbstraction is Script {
    function run() external returns (MultiSigAccountAbstraction deployed) {
        HelperConfig cfg = new HelperConfig();
        address ep = cfg.getActiveNetworkConfig().entryPoint;

        uint256 key1 = vm.envUint("PRIVATE_KEY_1");
        uint256 key2 = vm.envUint("PRIVATE_KEY_2");

        address owner1 = vm.addr(key1);
        address owner2 = vm.addr(key2);

        address[] memory owners = new address[](2);
        if (owner1 < owner2) {
            owners[0] = owner1;
            owners[1] = owner2;
        } else {
            owners[0] = owner2;
            owners[1] = owner1;
        }

        vm.startBroadcast(key1);
        deployed = new MultiSigAccountAbstraction(ep, owners);
        vm.stopBroadcast();

        console2.log("EntryPoint:", ep);
        console2.log("OwnerA:", owners[0]);
        console2.log("OwnerB:", owners[1]);
        console2.log("Deployed MultiSigAccountAbstraction:", address(deployed));
    }
}
