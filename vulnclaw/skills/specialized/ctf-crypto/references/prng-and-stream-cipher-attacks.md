# PRNG 与流密码攻击

## MT19937 ( Mersenne Twister ) 攻击

```python
# MT19937 状态恢复（给定 624 个输出）
from ctypes import *

def untemper(y):
    y ^= y >> 18
    y ^= (y << 15) & 0xefc60000
    y ^= (y << 7) & 0x9d2c5680
    y ^= (y << 14) & 0x9d2c5680
    y ^= (y << 13) & 0x9d2c5680
    y ^= (y << 11) & 0x9d2c5680
    y ^= y >> 18
    return y

def recover_mt(outputs):
    """从 624 个连续 MT19937 输出恢复内部状态"""
    state = [untemper(y) for y in outputs[:624]]
    MT = c_ulong * 624
    mt = MT(*state)
    index = 624
    def twist():
        global index, mt
        for i in range(227):
            y = (mt[i] & 0x80000000) + (mt[(i+1)%624] & 0x7fffffff)
            mt[i] = mt[(i+397) % 624] ^ (y >> 1)
            if y & 1:
                mt[i] ^= 0x9908b0df
        index = 0
    return mt, twist, index
```

## LCG (线性同余生成器) 攻击

```python
"""
LCG: s_{n+1} = a * s_n + c (mod m)
已知参数时：直接递推
未知参数时：已知 3 组 (s, s_next) 可求 a, c, m
"""

def lcg_attack(states):
    """从 3 个连续状态恢复 LCG 参数 (a, c, m)"""
    s0, s1, s2 = states[0], states[1], states[2]
    # s1 = a*s0 + c (mod m)
    # s2 = a*s1 + c (mod m)
    # s2 - s1 = a*(s1 - s0) (mod m)
    # 扩展欧几里得求 a, m
```

## LFSR (线性反馈移位寄存器) 攻击

```python
"""
Berlekamp-Massey 算法：从输出序列恢复 LFSR 反馈多项式
"""

def berlekamp_massey(s):
    """从二进制序列恢复 LFSR 最短反馈多项式"""
    # Sage 实现
    # F.<x> = GF(2)[]
    # s_seq = sequence(s)
    # return list(lfsr_sequence(f, [1]+[0]*15, len(s)))
```

## 已知明文攻击 (XOR 流密码)

```python
"""
流密码: C = P XOR keystream
如果知道部分明文 P，可以恢复 keystream = C XOR P
keystream 可用于解密其他密文
"""

def xor_attack(ciphertext, known_plaintext):
    """XOR 流密码已知明文攻击"""
    key = bytes(a ^ b for a, b in zip(ciphertext, known_plaintext))
    return key

def xor_decrypt(key, ciphertext):
    """用恢复的密钥流解密"""
    return bytes(a ^ b for a, b in zip(key, ciphertext))
```

## RC4 攻击

```python
"""
RC4 已知弱点：
1. RC4 Drop (丢弃前 N 字节后，密钥流接近随机)
2. 某些密钥初始化有偏差
"""

def rc4_drop(ciphertext, drop=3072):
    """RC4 Drop N 字节后解密"""
```

## Python random 模块预测

```python
import random

# 如果能访问 Python random 状态，可以预测未来随机数
# 已知 624 * 4 = 2496 字节的状态
state = random.getstate()
# 推进随机数
random.setstate(state)
next_val = random.randint(0, 2**31)
```

## 从数据反推生成参数与种子（正向重建）

**这是 numpy/torch 生成型附件题的第一反应，不是最后手段。** 先想"作者用什么参数生成的"，再去试排列/爆破。

判据：数据是**生成出来的**而不是自然采集的 —— `.npz`/`.pt`/`.npy` 附件、统计上接近正态/均匀、值有真实 float64 精度而非 float32 转来、大量精确重复行。

### 三步法

**1. 提统计量，猜简洁参数**

```python
import numpy as np
A = np.load("model_A.npz")
rows = np.unique(A["k5"], axis=0)        # 重复行去重后才是原型矩阵
print(rows.std())                        # 0.6096 -> sigma 很可能是 0.6
```

出题人用的都是**简洁数字**：`sigma ∈ {0.1, 0.5, 0.6, 0.7, 0.8, 1.0}`，`scale=1e3`，`size=(48,32)`。不要试图从标准差严格推导，直接列候选去试。

**2. 搜种子空间**

常见种子空间，按顺序试：

| 空间 | 规模 | 生成 |
|---|---|---|
| 小整数 | 0–10000 | `range(10000)` |
| `YYYYMMDD` 日期 | ~11k（2000–2031） | `int(day.strftime("%Y%m%d"))` |
| Unix 时间戳 | 按题目日期±30 天 | `int(ts)` |
| 文件名/题面数字 | 几个 | 手填 |

**3. 用单个锚点快速筛选**

只比一个数，不重建整个模型 —— 这一步把 11k 次全量生成压到可接受。

```python
from datetime import date, timedelta
import numpy as np

anchor = float(A["k5"][0, 0])       # 任一已知位置的原始值
target = anchor / 0.6               # 除以猜的 sigma，得标准化值

day, end = date(2000, 1, 1), date(2031, 1, 1)
while day < end:
    seed = int(day.strftime("%Y%m%d"))
    v = np.random.default_rng(seed).standard_normal(10_000)
    hits = np.flatnonzero(np.abs(v - target) < 2e-15)   # 容差要贴 float64 精度
    if len(hits):
        print(seed, hits)                                # 命中后必须全量复核
    day += timedelta(days=1)
```

命中后**必须重建全部数组逐位比对**，单点命中会有假阳性。

### NumPy 两代 API 要分开试

| API | 采样算法 | 特征 |
|---|---|---|
| `np.random.RandomState(seed).normal()` | legacy Box-Muller / polar | 老旧题目 |
| `np.random.default_rng(seed).standard_normal()` | PCG64 + Ziggurat | NumPy ≥1.17，**新题首选** |

`default_rng` 的 Ziggurat 快速分支是 `x = ± rabs * wi[index]`，`wi` 是固定常数表；如果数据里有大量同尺度的精确整数倍关系，说明走的是这条，也就确认了 `default_rng`。

### 找到 seed 之后

**不要再用排列/爆破反推。** 有了 seed + sigma 就能完整重建原数组，乱序题里"每个位置该是什么"直接读出来交差，复杂度从 O(n!) 降到 O(1)。

实测（强网杯 2026 NeuronShuffle）：题解 1 次种子搜索定位 `20261101`，而"从重复神经元枚举排列"的路线试了 53 万候选 × 51 种规则族，**全部失败** —— 排列空间远大于种子空间，选错范式就是纯浪费。

### 与"高熵=加密"的误判

附件看起来高熵（7.99 bit/byte）**不等于**它是加密数据。先问：

- 长度是否等于某个已知明文（同尺寸的 A/B 极可能是同一模型的两个版本）
- 有没有周期性 keystream
- 参数重建能不能解释它

"这份文件是噪声/加密的，这条路死了"这类否定结论，必须有**试过参数重建**的记录才算数。只因为"看不到 ZIP 头"就说不可恢复，是最常见的错误。
