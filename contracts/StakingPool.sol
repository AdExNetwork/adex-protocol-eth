// SPDX-License-Identifier: agpl-3.0
pragma solidity ^0.8.0;

interface ISupplyController {
	function mintIncentive() external returns (uint);
	function mintableIncentive(address owner) external view returns (uint);
}

interface IADXToken {
	function transfer(address to, uint256 amount) external returns (bool);
	function transferFrom(address from, address to, uint256 amount) external returns (bool);
	function approve(address spender, uint256 amount) external returns (bool);
	function balanceOf(address spender) external view returns (uint);
	function allowance(address owner, address spender) external view returns (uint);
	function supplyController() external view returns (ISupplyController);
}

interface IChainlinkSimple {
	function latestAnswer() external view returns (uint);
}

contract StakingPool {
	// ERC20 stuff
	// Constants
	string public constant name = "AdEx Staking Token";
	uint8 public constant decimals = 18;
	string public symbol = "ADX-STAKING";

	// @TODO: make this mutable?
	uint constant TIME_TO_UNBOND = 20 days;

	// Mutable variables
	uint public totalSupply;
	mapping(address => uint) balances;
	mapping(address => mapping(address => uint)) allowed;
	// How much ADX unlocks at a given time for each user
	mapping (address => mapping(uint => uint)) unlocksAt;

	// @TODO diret ref to supplyController

	// EIP 2612
	bytes32 public DOMAIN_SEPARATOR;
	// keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
	bytes32 public constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
	mapping(address => uint) public nonces;

	// ERC20 events
	event Approval(address indexed owner, address indexed spender, uint amount);
	event Transfer(address indexed from, address indexed to, uint amount);

	// Staking pool events
	event LogLeave(address indexed owner, uint unlockAt, uint amount);
	event LogSetGovernance(address indexed addr, bool hasGovt, uint time);

	// ERC20 methods
	function balanceOf(address owner) external view returns (uint balance) {
		return balances[owner];
	}

	function transfer(address to, uint amount) external returns (bool success) {
		require(to != address(this), 'BAD_ADDRESS');
		balances[msg.sender] = balances[msg.sender] - amount;
		balances[to] = balances[to] + amount;
		emit Transfer(msg.sender, to, amount);
		return true;
	}

	function transferFrom(address from, address to, uint amount) external returns (bool success) {
		balances[from] = balances[from] - amount;
		allowed[from][msg.sender] = allowed[from][msg.sender] - amount;
		balances[to] = balances[to] + amount;
		emit Transfer(from, to, amount);
		return true;
	}

	function approve(address spender, uint amount) external returns (bool success) {
		allowed[msg.sender][spender] = amount;
		emit Approval(msg.sender, spender, amount);
		return true;
	}

	function allowance(address owner, address spender) external view returns (uint remaining) {
		return allowed[owner][spender];
	}

	// EIP 2612
	function permit(address owner, address spender, uint amount, uint deadline, uint8 v, bytes32 r, bytes32 s) external {
		require(deadline >= block.timestamp, 'DEADLINE_EXPIRED');
		bytes32 digest = keccak256(abi.encodePacked(
			'\x19\x01',
			DOMAIN_SEPARATOR,
			keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, amount, nonces[owner]++, deadline))
		));
		address recoveredAddress = ecrecover(digest, v, r, s);
		require(recoveredAddress != address(0) && recoveredAddress == owner, 'INVALID_SIGNATURE');
		allowed[owner][spender] = amount;
		emit Approval(owner, spender, amount);
	}

	// Inner
	function innerMint(address owner, uint amount) internal {
		totalSupply = totalSupply + amount;
		balances[owner] = balances[owner] + amount;
		// Because of https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md#transfer-1
		emit Transfer(address(0), owner, amount);
	}
	function innerBurn(address owner, uint amount) internal {
		totalSupply = totalSupply - amount;
		balances[owner] = balances[owner] - amount;
		emit Transfer(owner, address(0), amount);
	}


	// Pool functionality
	IADXToken public ADXToken;
	mapping (address => bool) public governance;
	constructor(IADXToken token) {
		ADXToken = token;
		governance[msg.sender] = true;
		// EIP 2612
		uint chainId;
		assembly {
			chainId := chainid()
		}
		DOMAIN_SEPARATOR = keccak256(
			abi.encode(
				keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
				keccak256(bytes(name)),
				keccak256(bytes('1')),
				chainId,
				address(this)
			)
		);

		emit LogSetGovernance(msg.sender, true, block.timestamp);
	}

	// Governance functions
	function setGovernance(address addr, bool hasGovt) external {
		require(governance[msg.sender], 'NOT_GOVERNANCE');
		governance[addr] = hasGovt;
		emit LogSetGovernance(addr, hasGovt, block.timestamp);
	}

	// Pool stuff
	function shareValue() external view returns (uint) {
		if (totalSupply == 0) return 0;
		return (ADXToken.balanceOf(address(this)) + ADXToken.supplyController().mintableIncentive(address(this)))
			* 1e18
			/ totalSupply;
	}

	function enter(uint256 amount) external {
		// Please note that minting has to be in the beginning so that we take it into account
		// when using ADXToken.balanceOf()
		// Minting makes an external call but it's to a trusted contract (ADXToken)
		ADXToken.supplyController().mintIncentive();

		uint totalADX = ADXToken.balanceOf(address(this));

		// The totalADX == 0 check here should be redudnant; the only way to get totalSupply to a nonzero val is by adding ADX
		if (totalSupply == 0 || totalADX == 0) {
			innerMint(msg.sender, amount);
		} else {
			uint256 newShares = amount * totalSupply / totalADX;
			innerMint(msg.sender, newShares);
		}
		require(ADXToken.transferFrom(msg.sender, address(this), amount));
	}

	// @TODO: rename to stake/unskake?
	function leave(uint shares, bool skipMint) external {
		if (!skipMint) ADXToken.supplyController().mintIncentive();
		uint totalADX = ADXToken.balanceOf(address(this));
		uint adxAmount = shares * totalADX / totalSupply;
		uint willUnlockAt = block.timestamp + TIME_TO_UNBOND;
		// Note: we burn their shares but don't give them the ADX immediately - meaning this ADX will continue incurring rewards
		// for other stakers during the time, which is intended behavior
		innerBurn(msg.sender, shares);
		unlocksAt[msg.sender][willUnlockAt] += adxAmount;

		emit LogLeave(msg.sender, willUnlockAt, adxAmount);
	}

	function withdraw(uint willUnlockAt) external {
		require(block.timestamp > willUnlockAt, 'UNLOCK_TOO_EARLY');
		uint adxAmount = unlocksAt[msg.sender][willUnlockAt];
		require(adxAmount > 0, 'ZERO_AMOUNT');
		unlocksAt[msg.sender][willUnlockAt] = 0;
		require(ADXToken.transfer(msg.sender, adxAmount));
	}
}