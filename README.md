# SPIGNOLI High-Order Countermeasures for AES

We present masked implementations of the Advanced Encryption Standard (AES) written in the C programming language. These implementations incorporate various countermeasures, including:

- The classical Rivain-Prouff masking technique [RP10].
- S-Box computation using a lookup table approach [Cor14].
- The utilization of diverse robust Pseudo-Random Generator (PRG) constructions [CGZ20].
- The secure wire shuffling countermeasure [CS21].

----------------------------------------------------

## Notes

It should be noted that we do not make the claim that these implementations are inherently secure against t-th order attacks in practical scenarios. This repository includes implementations sourced from published works, timing comparisons, and personal learning experiences.

We emphasize that the code implementing the shuffling countermeasure is a personal version distinct from the one presented in [CS21]. Furthermore, the code implementing AES with table recomputation countermeasures and PRGs is a work in progress and remains incomplete.

The structure and file naming conventions within the folders may exhibit similarities, but they may also exhibit differences.

----------------------------------------------------

## References

[RP10] Matthieu Rivain and Emmanuel Prouff. "Provably Secure Higher-Order Masking of AES." In CHES, pp. 413–427, 2010.

[Cor14] Jean-Sébastien Coron. "Higher Order Masking of Look-up Tables." In Advances in Cryptology - EUROCRYPT 2014 - 33rd Annual International Conference on the Theory and Applications of Cryptographic Techniques, Copenhagen, Denmark, May 11-15, 2014. Proceedings, pp. 441–458, 2014.

[CGZ20] Jean-Sébastien Coron, Aurélien Greuet, and Rina Zeitoun. "Side-channel Masking with Pseudo-Random Generator." In Anne Canteaut and Yuval Ishai, editors, Advances in Cryptology – EUROCRYPT 2020, pp. 342–375, Cham, 2020. Springer International Publishing.

[CS21] Jean-Sébastien Coron and Lorenzo Spignoli. "Secure Wire Shuffling in the Probing Model." In Tal Malkin and Chris Peikert, editors, Advances in Cryptology – CRYPTO 2021, pp. 215–244, Cham, 2021. Springer International Publishing.
