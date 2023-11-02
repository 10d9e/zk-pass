# Chaum–Pedersen Interactive Zero Knowledge Protocol

The Chaum–Pedersen protocol is a cryptographic technique used for proving that two discrete logarithms are equal without revealing the actual value of the logarithms. This protocol, developed by David Chaum and Torben Pryds Pedersen, is particularly useful in the realm of digital signatures, secure voting systems, and other cryptographic applications where maintaining privacy and integrity is crucial.

## Overview

At its core, the Chaum–Pedersen protocol is a zero-knowledge proof, a method by which one party (the prover) can prove to another party (the verifier) that a statement is true, without conveying any additional information apart from the fact that the statement is indeed true.

In the context of discrete logarithms, consider two groups $\(G_1\)$ and $\(G_2\)$ of prime order $\(p\)$, with generators $\(g_1\)$ and $\(g_2\)$ respectively. The Chaum–Pedersen protocol allows the prover to demonstrate that for two elements $\(A \in G_1\)$ and $\(B \in G_2\)$, the discrete logarithms of $\(A\)$ to the base $\(g_1\)$ and $\(B\)$ to the base $\(g_2\)$ are equal, i.e., $\(\log_{g_1}A = \log_{g_2}B\)$, without revealing the actual logarithm value.

The Chaum–Pedersen protocol is a Sigma protocol designed to prove knowledge of discrete logarithms and their equality. Let's break down the protocol step by step to understand its components and how it ensures security and validity of the proof.

### Protocol Overview (Discrete Log)

Peggy (the prover) wants to prove to Victor (the verifier) that she knows two discrete logarithms $\( x_1 \)$ and $\( x_2 \)$ such that:

$\[ y_1 = g^{x_1} \quad \text{and} \quad y_2 = h^{x_2} \]$

and that $\( x_1 = x_2 = x \)$. Here, $\( g \)$ and $\( h \)$ are generators of groups of prime order $\( q \)$.

### Steps of the Chaum–Pedersen Protocol

1. **Commitment** ( $\( R(x, k) \)$ ):
   - Peggy chooses a random $\( k \)$ and computes the commitments:
     $\[ (r_1, r_2) = (g^k, h^k) \]$
   - She sends $\( (r_1, r_2) \)$ to Victor.

2. **Challenge**:
   - Victor sends a random challenge $\( c \)$ to Peggy.

3. **Response** ( $\( S(c, x, k) \)$ ):
   - Peggy computes the response:
     $\[ s = k - c \cdot x \mod q \]$
   - She sends $\( s \)$ to Victor.

4. **Verification** ( $\( V((r_1, r_2), c, s) \)$ ):
   - Victor checks if the following equations hold:
     $\[ r_1 = g^s \cdot y_1^c \quad \text{and} \quad r_2 = h^s \cdot y_2^c \]$
   - If both equations hold, the proof is accepted.

### Special Soundness

The protocol is specially sound under the assumption of an honest verifier. To show this, assume that Peggy manages to produce two valid transcripts for the same commitments $\( (t_1, t_2) \)$, but with different challenges $\( c_1 \)$ and $\( c_2 \)$, and valid responses $\( s_1 \)$ and $\( s_2 \)$. Then, from the verification equations, you get:

$\[ t_1 = g^{s_1} \cdot y_1^{c_1} = g^{s_2} \cdot y_1^{c_2} \]$
$\[ t_2 = h^{s_1} \cdot y_2^{c_1} = h^{s_2} \cdot y_2^{c_2} \]$

From this, you can derive:

$\[ y_1^{c_1 - c_2} = g^{s_2 - s_1} \]$
$\[ y_2^{c_2 - c_1} = h^{s_2 - s_1} \]$

Since $\( x_1 = x_2 = x \)$, it follows that:

$\[ x = \frac{c_1 - c_2}{s_2 - s_1} \mod q \]$

This means that if Peggy can produce two valid transcripts with different challenges for the same commitment, Victor can compute the discrete logarithm $\( x \)$, which contradicts the assumption that Peggy knows the discrete logarithm. Therefore, the protocol ensures that Peggy must indeed know the discrete logarithm.

### Adapting Chaum-Pedersen to Elliptic Curves:

Now, let's adapt the Chaum-Pedersen Protocol to elliptic curves. Assume we want to prove that the discrete logarithms of points $\(P\)$ and $\(Q\)$ to the bases $\(G\)$ and $\(H\)$, respectively, are equal, i.e., $\(G^x = P\)$ and $\(H^x = Q\)$ for some unknown $\(x\)$, without revealing $\(x\)$.

1. **Setup**: 
   - Public information: Points $\(G\)$, $\(H\)$, $\(P\)$, $\(Q\)$ on the elliptic curve.
   - Prover's secret: The value $\(x\)$, such that $\(G^x = P\)$ and $\(H^x = Q\)$.

2. **Commitment**:
   - The prover selects a random scalar $\(r\)$ and computes $\(A = G^r\)$ and $\(B = H^r\)$.
   - The prover sends $\(A\)$ and \(B\)$ to the verifier.

3. **Challenge**:
   - The verifier sends a random scalar $\(c\)$ as a challenge to the prover.

4. **Response**:
   - The prover computes $\(s = r + cx\)$ (where the addition and multiplication are in the scalar field).
   - The prover sends $\(s\)$ to the verifier.

5. **Verification**:
   - The verifier checks if $\(G^s = A \cdot P^c\)$ and $\(H^s = B \cdot Q^c\)$. This uses the property that $\(G^{r+cx} = G^r \cdot G^{cx}\)$.
   - If both equations hold, the verifier accepts the proof; otherwise, it is rejected.

### Zero-Knowledge Property

The protocol is zero-knowledge because any transcript produced by Peggy can be simulated by Victor without knowing the discrete logarithm. The simulator $\( S^* \)$ produces transcripts that are indistinguishable from a real transcript, ensuring that no information about the discrete logarithm is leaked during the protocol.

## Security and Applications

The Chaum–Pedersen protocol is secure under the discrete logarithm problem's hardness assumption. It ensures that a malicious prover cannot convince the verifier of a false statement without knowing the actual discrete logarithm.

Applications of the Chaum–Pedersen protocol include:

- **Digital Signatures**: Enhancing signature schemes with additional privacy features.
- **Secure Voting Systems**: Ensuring the integrity and secrecy of votes.
- **Cryptographic Protocols**: Providing zero-knowledge proofs in various cryptographic constructs.

## Conclusion

The Chaum–Pedersen protocol is a powerful tool in cryptography, providing a way to prove equality of discrete logarithms without compromising privacy. Its applications in secure communications and data protection highlight its significance in the ever-evolving landscape of digital security.

```markdown
# References
- Chaum, D., & Pedersen, T. P. (1992). Wallet databases with observers. In Advances in Cryptology—CRYPTO’92 (pp. 89-105). Springer, Berlin, Heidelberg.
- Goldreich, O. (2001). Foundations of Cryptography: Basic Tools. Cambridge University Press.
- Smart, N. (2003). Cryptography: An Introduction. McGraw-Hill Education.
```
