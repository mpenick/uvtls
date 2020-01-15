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

#ifndef UVTLS_INTERNAL_H
#define UVTLS_INTERNAL_H

#define UVTLS_RING_BUF_BLOCK_SIZE (16 * 1014 + 5)

typedef struct uvtls_ring_buf_s uvtls_ring_buf_t;
typedef struct uvtls_ring_buf_block_s uvtls_ring_buf_block_t;
typedef struct uvtls_ring_buf_pos_s uvtls_ring_buf_pos_t;

struct uvtls_ring_buf_pos_s {
  int index;
  uvtls_ring_buf_block_t* block;
};

struct uvtls_ring_buf_s {
  uvtls_ring_buf_pos_t tail;
  uvtls_ring_buf_pos_t head;
  uvtls_ring_buf_block_t* empty_blocks;
  int size;
  long ret;
};

struct uvtls_ring_buf_block_s {
  char data[UVTLS_RING_BUF_BLOCK_SIZE];
  uvtls_ring_buf_block_t* next;
};

#endif /* UVTLS_INTERNAL_H */
