// VulnerablePatterns.sol
// Intentionally vulnerable contract for testing analyzers
pragma solidity ^0.6.12;

contract VulnerablePatterns {
    mapping(address => uint256) public balances;
    address public owner;
    address public delegate; // attacker-controlled delegate target
    uint8 public counter;     // small type for overflow tests

    constructor() public {
        owner = msg.sender; // no zero-check (minor)
    }

    // ===== Vulnerability: Integer overflow (pre-0.8 arithmetic) =====
    function addToCounter(uint8 x) public {
        // using a small unsigned type in Solidity <0.8 allows overflow
        counter += x;
    }

    // ===== Vulnerability: Unchecked external call / Reentrancy =====
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "insufficient");
        // External call BEFORE state update -> reentrancy window
        (bool ok, ) = msg.sender.call{ value: amount }("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }

    // ===== Vulnerability: Authorization via tx.origin =====
    function setDelegate(address _d) public {
        // using tx.origin for auth is insecure (phishing via intermediate contracts)
        require(tx.origin == owner, "not owner");
        delegate = _d;
    }

    // ===== Vulnerability: delegatecall to untrusted/controllable address =====
    function execDelegate(bytes memory data) public {
        // delegate can be set by setDelegate — if attacker controls it, they get storage access
        // no checks on delegate or data
        delegate.delegatecall(data);
    }

    // ===== Vulnerability: Unprotected selfdestruct =====
    function kill() public {
        // anyone can call selfdestruct here and drain contract to their address
        selfdestruct(msg.sender);
    }

    // ===== Minor: public mapping exposes balances (info disclosure) =====
    // mapping is public (balances) — useful/intentional for some tests
}
