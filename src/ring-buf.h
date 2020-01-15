/* Copyright Michael A. Penick
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
