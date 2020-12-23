// SPDX-License-Identifier: agpl-3.0
pragma solidity ^0.8.0;

import "./libs/SafeERC20.sol";
import "./libs/MerkleProof.sol";
import "./libs/SignatureValidator.sol";

contract OUTPACE {
	// type, state, event, function

	// @TODO challene expiry date 
	enum ChannelState { Normal, Challenged, Closed }
	struct Channel {
		address leader;
		address follower;
		address tokenAddr;
		bytes23 nonce;
	}
	struct Withdrawal {
		Channel channel;
		uint balanceTreeAmount;
		bytes32 stateRoot;
		bytes32[3] sigLeader;
		bytes32[3] sigFollower;
		bytes32[] proof;
	}
	struct BalanceLeaf {
		address earner;
		uint amount;
	}

 	// channelId => channelState
	mapping (bytes32 => ChannelState) public states;
	
	// remaining per channel (channelId => uint)
	mapping (bytes32 => uint) public remaining;
	// withdrawn per channel user (channelId => (account => uint))
	mapping (bytes32 => mapping (address => uint)) public withdrawnPerUser;
	// deposits per channel (channelId => (depositId => uint))
	mapping (bytes32 => mapping (bytes32 => uint)) public deposits;

	// events
	// @TODO should we emit the full channel?
	event LogChannelDeposit(bytes32 indexed channelId, uint amount);


	// @TODO
	// event design, particularly for withdrawal
	// safeerc20
	// withdraw: verification
	// protocol params - make it an optional dependency


	function open(Channel calldata channel, bytes32 depositId, uint amount) external {
		bytes32 channelId = keccak256(abi.encode(channel));
		require(amount > 0, 'zero deposit');
		require(deposits[channelId][depositId] == 0, 'deposit already exists');
		require(states[channelId] == ChannelState.Normal, 'channel is closed or challenged');
		remaining[channelId] = remaining[channelId] + amount;
		deposits[channelId][depositId] = amount;

		SafeERC20.transferFrom(channel.tokenAddr, msg.sender, address(this), amount);
		emit LogChannelDeposit(channelId, amount);
	}

	function withdraw(address earner, address to, Withdrawal[] calldata withdrawals) external {
		require(withdrawals.length > 0, 'no withdrawals');
		uint toWithdraw;
		address tokenAddr = withdrawals[0].channel.tokenAddr;
		for (uint i = 0; i < withdrawals.length; i++) {
			Withdrawal calldata withdrawal = withdrawals[i];
			// require channel is not closed
			require(withdrawal.channel.tokenAddr == tokenAddr, 'only one token can be withdrawn');
			bytes32 channelId = keccak256(abi.encode(withdrawal.channel));
			require(states[channelId] != ChannelState.Closed, 'channel is not closed');

			bytes32 hashToSign = keccak256(abi.encode(channelId, withdrawal.stateRoot));
			require(SignatureValidator.isValidSignature(hashToSign, withdrawal.channel.leader, withdrawal.sigLeader), 'leader sig');
			require(SignatureValidator.isValidSignature(hashToSign, withdrawal.channel.follower, withdrawal.sigFollower), 'follower sig');

			// check the merkle proof
			bytes32 balanceLeaf = keccak256(abi.encode(earner, withdrawal.balanceTreeAmount));
			require(MerkleProof.isContained(balanceLeaf, withdrawal.proof, withdrawal.stateRoot), 'balance leaf not found');

			uint toWithdrawChannel = withdrawal.balanceTreeAmount - withdrawnPerUser[channelId][earner];
			toWithdraw += toWithdrawChannel;

			// Update storage
			withdrawnPerUser[channelId][earner] = withdrawal.balanceTreeAmount;
			remaining[channelId] -= toWithdrawChannel;
		}
		// Do not allow to change `to` if the caller is not the earner
		// @TODO test for this
		if (earner != msg.sender) to = earner;
		SafeERC20.transfer(tokenAddr, to, toWithdraw);
	}

	function challenge(Channel calldata channel) external {
		require(msg.sender == channel.leader || msg.sender == channel.follower, 'only validators can challenge');
		bytes32 channelId = keccak256(abi.encode(channel));
		states[channelId] = ChannelState.Challenged;
		// @TODO set the time during which the challenge was made
	}

	// @NOTE: what if balance trees get too big - we have to calculate
	function resume(Channel calldata channel, BalanceLeaf[] calldata tree, bytes32[3][3] calldata sigs) external {
		// @NOTE: can we have type aliases for bytes32[3]
		// @NOTE: we don't have the sum of all deposits so we'll have to compute it frm withdrawnPerUser + remaining
		// what if we don't aggr the total deposits, and we miss certain earners - should be OK, we only care to prove if we've distributed all remaining
		// that way proofs can be smaller as well! because we can omit every leaf for which withdrawnPerUser is equal to it
		// but the gas implications in this case are interesting...
		// Nah - we can't skip leaves because that way sigs won't work
		// >> in conclusion we'll just have to keep an aggregate of total deposits per channel - that way we solve everything <<
	}

	function close(Channel calldata channel) external {
		// @TODO check if enough time has passed
		// @TODO liquidator, send remaining funds to it
	}
}