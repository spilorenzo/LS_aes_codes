# SPIGNOLI High-Order Countermeasures for AES

We provide masked AES implementations, coded in language C, based on different countermeasures:

- the classical Rivain-Prouff masking [RP10];
- the S-Box computation via lookup table [Cor14];
- the use of different (robust) PRG constructions [CGZ20];
- the shuffling countermeasure [CS21].

----------------------------------------------------

## Notes

We do not claim that in practice the implementation would be secure against a t-th order attack. The repository contains implementations collected from publications, timing comparisons and personal learning. 

We stress the fact that: the code implementing the shuffling countermeasure is my personal version and it is diffenrent from the one provided in [CS21]; the code implementing AES with the table recomputation countermeasure and the PRGs is a working-in-progress and it is not complited.

The structure and the naming of the files of the folders are very similar but they may have differencies.

----------------------------------------------------

## References

[RP10] Matthieu Rivain and Emmanuel Prouff. Provably secure higher-order masking of AES. In CHES, pages 413–427, 2010.

[Cor14] Jean-Sébastien Coron. Higher order masking of look-up tables. In Advances in Cryptology - EUROCRYPT 2014 - 33rd Annual International Conference on the Theory and Applications of Cryptographic Techniques, Copenhagen, Denmark, May 11-15, 2014. Proceedings, pages 441–458, 2014.

[CGZ20] Jean-Sébastien Coron, Aurélien Greuet, and Rina Zeitoun. Side-channel masking with pseudo-random generator. In Anne Canteaut and Yuval Ishai, editors, Ad- vances in Cryptology – EUROCRYPT 2020, pages 342–375, Cham, 2020. Springer International Publishing.

[CS21] Jean-Sébastien Coron and Lorenzo Spignoli. Secure wire shuffling in the probing model. In Tal Malkin and Chris Peikert, editors, Advances in Cryptology – CRYPTO 2021, pages 215–244, Cham, 2021. Springer International Publishing.


