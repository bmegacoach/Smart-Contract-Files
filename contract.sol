// Fixed.sol
// Hardened version (safe-by-default): SPDX, pragma, naming, checks, reentrancy guard, checked low-level calls
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CallerFixed {
    address public immutable fixedAddress;
    address public storedAddress;
    uint256 public statevar;

    // simple reentrancy guard
    uint8 private _status;
    uint8 private constant _NOT_ENTERED = 1;
    uint8 private constant _ENTERED = 2;

    event ExternalCall(address indexed target, bool success, bytes data);
    event StoredAddressUpdated(address indexed oldAddress, address indexed newAddress);

    constructor(address addr) {
        require(addr != address(0), "Invalid fixed address");
        fixedAddress = addr;
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        require(_status != _ENTERED, "Reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }

    // Example of safe checked low-level call (still low-level, but check result)
    function thisIsFine() public returns (bool) {
        (bool success, bytes memory data) = fixedAddress.call("");
        emit ExternalCall(fixedAddress, success, data);
        require(success, "External call failed");
        return success;
    }

    // Checks-Effects-Interactions + nonReentrant
    function reentrancy() public nonReentrant {
        // effect first
        statevar = 0;

        // interaction after state effects
        (bool success, bytes memory data) = fixedAddress.call("");
        emit ExternalCall(fixedAddress, success, data);
        require(success, "External call failed");
    }

    function callUserAddress(address addr) public nonReentrant returns (bool) {
        require(addr != address(0), "Invalid address");
        (bool success, bytes memory data) = addr.call("");
        emit ExternalCall(addr, success, data);
        require(success, "External call failed");
        return success;
    }

    function callStoredAddress() public nonReentrant returns (bool) {
        require(storedAddress != address(0), "Stored address not set");
        (bool success, bytes memory data) = storedAddress.call("");
        emit ExternalCall(storedAddress, success, data);
        require(success, "External call failed");
        return success;
    }

    function setStoredAddress(address addr) public {
        require(addr != address(0), "Invalid address");
        address old = storedAddress;
        storedAddress = addr;
        emit StoredAddressUpdated(old, addr);
    }
}
