// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import { Script } from "forge-std/Script.sol";
import { console2 } from "forge-std/console2.sol";
import { MockEntryPoint } from "test/mocks/MockEntryPoint.sol";
import { MockERC20 } from "test/mocks/MockERC20.sol";

contract HelperConfig is Script {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/
    error HelperConfig__InvalidChainId(uint256 chainId);

    /*//////////////////////////////////////////////////////////////
                                 TYPES
    //////////////////////////////////////////////////////////////*/
    struct NetworkConfig {
        address entryPoint; // ERC-4337 EntryPoint for EVM chains (0x0 for zkSync native AA)
        address usdc; // Only used by demo scripts; can be 0x0 on chains where you don't have a token
    }

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/
    uint256 internal constant ETH_MAINNET_CHAIN_ID = 1;
    uint256 internal constant ETH_SEPOLIA_CHAIN_ID = 11_155_111;

    uint256 internal constant ARBITRUM_MAINNET_CHAIN_ID = 42_161;

    uint256 internal constant ZKSYNC_MAINNET_CHAIN_ID = 324;
    uint256 internal constant ZKSYNC_SEPOLIA_CHAIN_ID = 300;

    uint256 internal constant ANVIL_CHAIN_ID = 31_337;
    uint256 internal constant HARDHAT_CHAIN_ID = 1337;

    // Local network state variables
    NetworkConfig internal localNetworkConfig;

    // chainId => config
    mapping(uint256 chainId => NetworkConfig) public networkConfigs;

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    constructor() {
        networkConfigs[ETH_MAINNET_CHAIN_ID] = getEthMainnetConfig();
        networkConfigs[ETH_SEPOLIA_CHAIN_ID] = getEthSepoliaConfig();

        networkConfigs[ARBITRUM_MAINNET_CHAIN_ID] = getArbMainnetConfig();

        networkConfigs[ZKSYNC_MAINNET_CHAIN_ID] = getZkSyncConfig();
        networkConfigs[ZKSYNC_SEPOLIA_CHAIN_ID] = getZkSyncSepoliaConfig();
    }

    function getConfigByChainId(uint256 chainId) public returns (NetworkConfig memory) {
        NetworkConfig memory cfg = networkConfigs[chainId];

        // IMPORTANT:
        // - zkSync configs intentionally have entryPoint == address(0)
        // So we treat "configured" as: either field is non-zero.
        if (cfg.entryPoint != address(0) || cfg.usdc != address(0)) {
            return cfg;
        }

        // Only auto-create mocks on local chains.
        if (chainId == ANVIL_CHAIN_ID || chainId == HARDHAT_CHAIN_ID) {
            return getOrCreateAnvilEthConfig();
        }

        revert HelperConfig__InvalidChainId(chainId);
    }

    function getActiveNetworkConfig() public returns (NetworkConfig memory) {
        return getConfigByChainId(block.chainid);
    }

    /*//////////////////////////////////////////////////////////////
                                CONFIGS
    //////////////////////////////////////////////////////////////*/
    function getEthMainnetConfig() public pure returns (NetworkConfig memory) {
        // ERC-4337 EntryPoint v0.7
        return NetworkConfig({
            entryPoint: 0x0000000071727De22E5E9d8BAf0edAc6f37da032, usdc: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
        });
    }

    function getEthSepoliaConfig() public pure returns (NetworkConfig memory) {
        // ERC-4337 EntryPoint v0.7 (deterministic address)
        // NOTE: There is no canonical USDC on Sepolia; keep usdc = address(0).
        // Your userOp script should read TOKEN_ADDRESS from .env instead.
        return NetworkConfig({ entryPoint: 0x0000000071727De22E5E9d8BAf0edAc6f37da032, usdc: address(0) });
    }

    function getArbMainnetConfig() public pure returns (NetworkConfig memory) {
        return NetworkConfig({
            entryPoint: 0x0000000071727De22E5E9d8BAf0edAc6f37da032, usdc: 0xaf88d065e77c8cC2239327C5EDb3A432268e5831
        });
    }

    function getZkSyncConfig() public pure returns (NetworkConfig memory) {
        // zkSync supports native AA, so no EntryPoint needed.
        // usdc here is just a placeholder from the lesson.
        return NetworkConfig({ entryPoint: address(0), usdc: 0x1d17CBcF0D6D143135aE902365D2E5e2A16538D4 });
    }

    function getZkSyncSepoliaConfig() public pure returns (NetworkConfig memory) {
        // zkSync Sepolia supports native AA, so no EntryPoint needed.
        // usdc is not guaranteed; treat it as placeholder.
        return NetworkConfig({ entryPoint: address(0), usdc: 0x1d17CBcF0D6D143135aE902365D2E5e2A16538D4 });
    }

    function getOrCreateAnvilEthConfig() public returns (NetworkConfig memory) {
        if (localNetworkConfig.entryPoint != address(0)) {
            return localNetworkConfig;
        }

        console2.log(unicode"⚠️ Deploying mock contracts (local chain only).");

        MockEntryPoint entryPoint = new MockEntryPoint();
        console2.log("Created new MockEntryPoint:", address(entryPoint));

        MockERC20 usdc = new MockERC20();
        console2.log("Created new MockERC20:", address(usdc));

        localNetworkConfig = NetworkConfig({ entryPoint: address(entryPoint), usdc: address(usdc) });

        return localNetworkConfig;
    }
}
