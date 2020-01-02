#ifndef UVTLS_RING_BUF_H
#define UVTLS_RING_BUF_H

#include "uvtls/internal.h"

#include <uv.h>

uvtls_ring_buf_pos_t uvtls_ring_buf_pos_init(int index,
                                             uvtls_ring_buf_block_t* block);

int uvtls_ring_buf_init(uvtls_ring_buf_t* rb);

void uvtls_ring_buf_destroy(uvtls_ring_buf_t* rb);

int uvtls_ring_buf_size(const uvtls_ring_buf_t* rb);

void uvtls_ring_buf_reset(uvtls_ring_buf_t* rb);

void uvtls_ring_buf_write(uvtls_ring_buf_t* rb, const char* data, int size);

int uvtls_ring_buf_tail_block(uvtls_ring_buf_t* rb, char** data, int size);

void uvtls_ring_buf_tail_block_commit(uvtls_ring_buf_t* rb, int size);

int uvtls_ring_buf_read(uvtls_ring_buf_t* rb, char* data, int len);

uvtls_ring_buf_pos_t uvtls_ring_buf_head_blocks(const uvtls_ring_buf_t* rb,
                                                uvtls_ring_buf_pos_t pos,
                                                uv_buf_t* bufs,
                                                int* bufs_count);

void uvtls_ring_buf_head_blocks_commit(uvtls_ring_buf_t* rb,
                                       uvtls_ring_buf_pos_t pos);

#endif /* UVTLS_RING_BUF_H */
