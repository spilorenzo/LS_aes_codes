//
//  sparse.h
//  AES_shuffling
//
//  Created by Lorenzo SPIGNOLI on 20/02/21.
//

#ifndef sparse_h
#define sparse_h

#include "shares.h"

// number of sparse shares
#define ell 6
#define dummy_value '$'

typedef byte sparse[ell+1];
typedef sparse sparse_shares[m+1];


void copy_sparse(sparse input, sparse output);
void copy_sparse_shares(sparse_shares input, sparse_shares output);

void random_sparse(sparse new_sparse);
void create_sparse(sparse new_sparse, byte value);

void cyclic_shift(sparse x_sparse, int new_index);

void xor_shuff(sparse a_sparse, sparse b_sparse, sparse c_sparse);
void mult_shuff(sparse a_sparse, sparse b_sparse, sparse c_sparse);

void square_shuff(sparse_shares x_sparse);

void sec_mult_shuff(sparse_shares a_sparse, sparse_shares b_sparse, sparse_shares c_sparse);
void sec_xor_shuff(sparse_shares a_sparse, sparse_shares b_sparse, sparse_shares c_sparse);
void sec_xtime_shuff(sparse_shares x_sparse);

void refresh_masks_shuff(sparse_shares x_sparse);

void sec_e254_shuff(sparse_shares x_sparse);

void sec_sbox_shuff(sparse_shares x_sparse);
void sec_rsbox_shuff(sparse_shares x_sparse);

#endif /* sparse_h */
