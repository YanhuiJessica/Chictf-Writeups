---
title: Crypto - Casino
description: 2022 | Hacky Easter | crypto
---

## 题目

Wanna try your luck in our new casino?

To prove we're not cheating, we are publishing our source code.

Connect to the server and start gamblin'!

    nc 46.101.107.117 2212

Note: The service is restarted every hour at x:00.

??? note "server.sage"

    ```sage
    from random import randint
    from secrets import flag
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Util.Padding import pad

    class RNG:
        def __init__(self):
            p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
            b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
            self.curve = EllipticCurve(GF(p), [-3,b])

            self.P = self.curve.lift_x(15957832354939571418537618117378383777560216674381177964707415375932803624163)
            self.Q = self.curve.lift_x(66579344068745538488594410918533596972988648549966873409328261501470196728491)
            
            self.state = randint(1, 2**256)
            
        def next(self):
            r = (self.state * self.P)[0].lift()
            self.state = (r * self.P)[0].lift()
            return (r * self.Q)[0].lift() >> 8

    class Casino:
        def __init__(self, rng):
            self.rng = rng
            self.balance = 10

        def play(self):
            print("Your bet: ", end='')
            bet = input()
            if (bet in ["0", "1"]):
                bet = Integer(bet)
                if (self.rng.next() % 2 == bet):
                    self.balance += 1
                else:
                    self.balance -= 1
                    if (self.balance == 0):
                        print("You are broke... play again")
                        exit()
                print(f"Your current balance: {self.balance}")
            else:
                print("Invalid bet option, use either 0 or 1")
                
        def buy_flag(self):
            if (self.balance >= 1337):
                key = SHA256.new(str(self.rng.next()).encode('ascii')).digest()
                cipher = AES.new(key, AES.MODE_ECB)
                print(cipher.encrypt(pad(flag.encode('ascii'), 16)).hex())
            else:
                print("No flag for the poor. Gamble more")

    def main():
        rng = RNG()
        casino = Casino(rng)

        print("Welcome to the Casino")
        print(f"Your id is {rng.next()}")
        print("What would you like to do?")
        print("(p)lay and win some money")
        print("(b)uy the flag")

        while (True):
            print("> ", end='')
            option = input()

            if (not option in ["b", "p"]):
                print("Unknown option, use 'b' or 'p'")
            elif (option == "b"):
                casino.buy_flag()
            elif (option == "p"):
                casino.play()

    if __name__ == '__main__':
        main()
    ```

## 解题思路

- 简单扫一眼代码，可以确定 `RNG` 里定义的椭圆曲线及点是特殊的。在不考虑初始余额的情况下，需要连续猜对 $1337$ 次才能拿到 Flag，因此 `next` 的输出一定是可预测的
- 首先想到看看「点的阶」，发现 $P$ 和 $Q$ 的阶都是 $ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551_{16}$，对应了特殊的椭圆曲线 [`NIST P-256`](https://safecurves.cr.yp.to/base.html)，但知道了是特殊的椭圆曲线有什么用呢 > <
- 使用 `NIST P-256` 进一步搜索发现它可以用在 `Dual_EC_DRBG`，而 `Dual_EC_DRBG` 存在后门，知道当前状态的完整输出，就可以推出下一状态 \\(ΦωΦ)/
- 结合 `Dual_EC_DRBG` 分析 `Casino` 使用的 `RNG`
    - 定义函数 $X(x,y)=x$，提取椭圆曲线上点的 $X$ 轴坐标
    - 状态 $s$ 的转移过程：$r_i=X(s_i P),s_{i+1}=X(r_i P)$
    - 第 $i$ 个「随机数」为 $X(r_i Q) \gg 8$
    - 存在整数 $e$ 使得 $eQ=P$，设 $t=X(r_i Q)$，点 $A$ 在椭圆曲线上且 $X(A)=t$，由此就能推出下一状态了 🥳 $X(eA)=X(e\times r_i Q)=X(r_i P)=s_{i+1}$
- 接下来思路就很清晰啦 XD 首先，尝试求出 $e$，再根据初始 `id` 和后续几次 `bet` 确定 $X(r_i Q)$ 未知的部分，最后攒钱 `buy_flag`！
    - 说不定 `self.balance >= 1337` 其实是在暗示 $e$，不过做的时候没注意 (ŏωŏ)

    ```py
    from sage.all import *
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    import pwn

    e = None
    p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
    b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    curve = EllipticCurve(GF(p), [-3, b])
    P = curve.lift_x(Integer(15957832354939571418537618117378383777560216674381177964707415375932803624163))
    Q = curve.lift_x(Integer(66579344068745538488594410918533596972988648549966873409328261501470196728491))

    def get_state(ts):
        '''
        Get possible next states from current RNG.next() output
        '''
        state = []
        for t in ts:
            try:
                A = curve.lift_x(Integer(t))
            except:
                # some x-coordinate values don't have the corresponding points on the curve
                continue
            state.append((e * A)[0].lift())
        return state

    def get_next(state):
        '''
        Get bet(s) and next state(s) from current state(s)
        '''
        bets, nxt = [], []
        for s in state:
            r = (s * P)[0].lift()
            nxt.append((r * P)[0].lift())
            bets.append((r * Q)[0].lift())
        return bets, nxt

    def remove_state(bets, state, false_bet):
        correct = []
        for b, s in zip(bets, state):
            if (b >> 8) % 2 != false_bet:
                correct.append(s)
        return correct

    if __name__ == '__main__':

        for i in range(2000):
            if i * Q == P:
                e = i   # 1337
                break

        conn = pwn.remote("46.101.107.117", 2212)

        balance = 10
        _id = conn.recvline_contains('Your id is').decode()
        t = int(_id[11:])

        ts = [(t << 8) + i for i in range(2 ** 8)]
        state = get_state(ts)

        while balance < 1337:
            conn.sendafter('> ', 'p\n')
            bets, state = get_next(state)
            bet = (bets[0] >> 8) % 2
            conn.sendafter('Your bet: ', str(bet) + '\n')
            curr_balance = conn.recvline_contains('balance').decode()
            curr_balance = int(curr_balance[curr_balance.find(': ') + 2:])
            if len(bets) > 1:
                if curr_balance < balance:
                    state = remove_state(bets, state, bet)
                else:
                    state = remove_state(bets, state, 0 if bet else 1)
            balance = curr_balance

        conn.sendafter('> ', 'b\n')
        enc_flag = conn.recvline().decode()
        bets, _ = get_next(state)
        key = SHA256.new(str(bets[0] >> 8).encode('ascii')).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        print(cipher.decrypt(bytes.fromhex(enc_flag)))
        # b'he2022{C4S1N0_B4CKD00R_ST0NK5}\x02\x02'
    ```

### Flag

> he2022{C4S1N0_B4CKD00R_ST0NK5}

## 参考资料

- [Dual_EC_DRBG - Wikipedia](https://en.wikipedia.org/wiki/Dual_EC_DRBG)
- [On the Possibility of a Back Door in the NIST SP800-90 Dual Ec Prng](http://rump2007.cr.yp.to/15-shumow.pdf)