// SPDX-License-Identifier: agpl-3.0
pragma solidity ^0.8.0;

import "./libs/SafeERC20.sol";
import "./libs/SignatureValidator.sol";

contract Identity {

	mapping (address => bool) public privileges;
	// The next allowed nonce
	uint public nonce = 0;

	// Events
	event LogPrivilegeChanged(address indexed addr, bool priv);

	// Transaction structure
	// Those can be executed by keys with >= PrivilegeLevel.Transactions
	// Even though the contract cannot receive ETH, we are able to send ETH (.value), cause ETH might've been sent to the contract address before it's deployed
	struct Transaction {
		// replay protection
		address identityContract;
		uint nonce;
		// tx fee, in tokens
		address feeTokenAddr;
		uint feeAmount;
		// all the regular txn data
		address to;
		uint value;
		bytes data;
	}

	constructor(address[] memory addrs) {
		uint len = addrs.length;
		for (uint i=0; i<len; i++) {
			privileges[addrs[i]] = true;
			emit LogPrivilegeChanged(addrs[i], true);
		}
	}

	// This contract can accept ETH
	function fallback() external payable {}

	function setAddrPrivilege(address addr, bool priv)
		external
	{
		require(msg.sender == address(this), 'ONLY_IDENTITY_CAN_CALL');
		privileges[addr] = priv;
		emit LogPrivilegeChanged(addr, priv);
	}

	function execute(Transaction[] memory txns, bytes32[3][] memory signatures)
		public
	{
		require(txns.length > 0, 'MUST_PASS_TX');
		address feeTokenAddr = txns[0].feeTokenAddr;
		uint feeAmount = 0;
		uint len = txns.length;
		for (uint i=0; i<len; i++) {
			Transaction memory txn = txns[i];
			require(txn.identityContract == address(this), 'TRANSACTION_NOT_FOR_CONTRACT');
			require(txn.feeTokenAddr == feeTokenAddr, 'EXECUTE_NEEDS_SINGLE_TOKEN');
			require(txn.nonce == nonce, 'WRONG_NONCE');

			// If we use the naive abi.encode(txn) and have a field of type `bytes`,
			// there is a discrepancy between ethereumjs-abi and solidity
			// if we enter every field individually, in order, there is no discrepancy
			//bytes32 hash = keccak256(abi.encode(txn));
			bytes32 hash = keccak256(abi.encode(txn.identityContract, txn.nonce, txn.feeTokenAddr, txn.feeAmount, txn.to, txn.value, txn.data));
			address signer = SignatureValidator.recoverAddr(hash, signatures[i]);

			require(privileges[signer] == true, 'INSUFFICIENT_PRIVILEGE_TRANSACTION');

			// NOTE: we have to change nonce on every txn: do not be tempted to optimize this by incrementing it once by the full txn count
			// otherwise reentrancies are possible, and/or anyone who is reading nonce within a txn will read a wrong value
			nonce = nonce + 1;
			feeAmount = feeAmount + txn.feeAmount;

			executeCall(txn.to, txn.value, txn.data);
			// The actual anti-bricking mechanism - do not allow a signer to drop his own priviledges
			require(privileges[signer] == true, 'PRIVILEGE_NOT_DOWNGRADED');
		}
		if (feeAmount > 0) {
			SafeERC20.transfer(feeTokenAddr, msg.sender, feeAmount);
		}
	}

	function executeBySender(Transaction[] memory txns)
		public
	{
		require(privileges[msg.sender] == true, 'INSUFFICIENT_PRIVILEGE_SENDER');
		uint len = txns.length;
		for (uint i=0; i<len; i++) {
			Transaction memory txn = txns[i];
			require(txn.nonce == nonce, 'WRONG_NONCE');

			nonce = nonce + 1;

			executeCall(txn.to, txn.value, txn.data);
		}
		// The actual anti-bricking mechanism - do not allow the sender to drop his own priviledges
		require(privileges[msg.sender] == true, 'PRIVILEGE_NOT_DOWNGRADED');
	}

	// we shouldn't use address.call(), cause: https://github.com/ethereum/solidity/issues/2884
	// copied from https://github.com/uport-project/uport-identity/blob/develop/contracts/Proxy.sol
	// there's also
	// https://github.com/gnosis/MultiSigWallet/commit/e1b25e8632ca28e9e9e09c81bd20bf33fdb405ce
	// https://github.com/austintgriffith/bouncer-proxy/blob/master/BouncerProxy/BouncerProxy.sol
	// https://github.com/gnosis/safe-contracts/blob/7e2eeb3328bb2ae85c36bc11ea6afc14baeb663c/contracts/base/Executor.sol
	function executeCall(address to, uint256 value, bytes memory data)
		internal
	{
		assembly {
			let result := call(gas(), to, value, add(data, 0x20), mload(data), 0, 0)

			switch result case 0 {
				let size := returndatasize()
				let ptr := mload(0x40)
				returndatacopy(ptr, 0, size)
				revert(ptr, size)
			}
			default {}
		}
	}
}
