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

#include "ring-buf.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

uvtls_ring_buf_pos_t uvtls_ring_buf_pos_init(int index,
                                             uvtls_ring_buf_block_t* block) {
  uvtls_ring_buf_pos_t pos;
  pos.index = index;
  pos.block = block;
  return pos;
}

static void free_blocks(uvtls_ring_buf_block_t* blocks) {
  uvtls_ring_buf_block_t* current = blocks;
  while (current) {
    uvtls_ring_buf_block_t* next = current->next;
    free(current);
    current = next;
  }
}

static uvtls_ring_buf_block_t* create_block() {
  uvtls_ring_buf_block_t* block =
      (uvtls_ring_buf_block_t*) malloc(sizeof(uvtls_ring_buf_block_t));
  block->next = NULL;
  return block;
}

static void push_tail_block(uvtls_ring_buf_t* rb) {
  if (rb->empty_blocks) {
    uvtls_ring_buf_block_t* empty_block = rb->empty_blocks;
    rb->tail.block->next = empty_block;
    rb->empty_blocks = empty_block->next;
    empty_block->next = NULL;
  } else {
    rb->tail.block->next = create_block();
  }
  rb->tail.block = rb->tail.block->next;
  rb->tail.index = 0;
}

static void pop_head_block(uvtls_ring_buf_t* rb) {
  uvtls_ring_buf_block_t* empty_block = rb->empty_blocks;
  uvtls_ring_buf_block_t* head_block = rb->head.block;
  rb->empty_blocks = head_block;
  rb->head.block = head_block->next;
  head_block->next = empty_block;
  rb->head.index = 0;
}

int uvtls_ring_buf_init(uvtls_ring_buf_t* rb) {
  uvtls_ring_buf_block_t* block = create_block();
  if (!block) {
    return UV_ENOMEM;
  }
  rb->empty_blocks = NULL;
  rb->head = rb->tail = uvtls_ring_buf_pos_init(0, block);
  rb->size = 0;
  rb->ret = -1;
  return 0;
}

void uvtls_ring_buf_destroy(uvtls_ring_buf_t* rb) {
  free_blocks(rb->empty_blocks);
  free_blocks(rb->head.block);
}

int uvtls_ring_buf_size(const uvtls_ring_buf_t* rb) {
  return rb->size;
}

void uvtls_ring_buf_reset(uvtls_ring_buf_t* rb) {
  while (rb->head.block != rb->tail.block) {
    pop_head_block(rb);
  }
  rb->head.index = rb->tail.index = 0;
  rb->size = 0;
}

void uvtls_ring_buf_write(uvtls_ring_buf_t* rb, const char* data, int size) {
  const char* pos = data;
  int remaining = size;
  assert(rb->tail.block && "Tail block should never be NULL");

  while (remaining > 0) {
    int to_copy = UVTLS_RING_BUF_BLOCK_SIZE - rb->tail.index;
    assert(rb->tail.index <= UVTLS_RING_BUF_BLOCK_SIZE &&
           "Tail index should always be less than or equal to block size");

    if (to_copy == 0) {
      push_tail_block(rb);
      to_copy = UVTLS_RING_BUF_BLOCK_SIZE;
    }

    if (to_copy > remaining) {
      to_copy = remaining;
    }

    memcpy(rb->tail.block->data + rb->tail.index, pos, (unsigned) to_copy);

    rb->tail.index += to_copy;
    rb->size += to_copy;
    pos += to_copy;
    remaining -= to_copy;
  }
}

int uvtls_ring_buf_tail_block(uvtls_ring_buf_t* rb, char** data, int size) {
  int available = UVTLS_RING_BUF_BLOCK_SIZE - rb->tail.index;
  assert(rb->tail.block && "Tail block should never be NULL");
  assert(rb->tail.index <= UVTLS_RING_BUF_BLOCK_SIZE &&
         "Tail index should always be less than or equal to block size");

  if (available == 0) {
    push_tail_block(rb);
    available = UVTLS_RING_BUF_BLOCK_SIZE;
  }

  *data = rb->tail.block->data + rb->tail.index;

  return size > available ? available : size;
}

void uvtls_ring_buf_tail_block_commit(uvtls_ring_buf_t* rb, int size) {
  int available = UVTLS_RING_BUF_BLOCK_SIZE - rb->tail.index;
  int to_commit = size;
  assert(rb->tail.block && "Tail block should never be NULL");
  if (to_commit > available) {
    to_commit = available;
  }
  rb->tail.index += to_commit;
  rb->size += to_commit;
  assert(rb->tail.index <= UVTLS_RING_BUF_BLOCK_SIZE &&
         "Tail index should always be less than or equal to block size");
}

int uvtls_ring_buf_read(uvtls_ring_buf_t* rb, char* data, int len) {
  int initial_size = rb->size;
  char* pos = data;
  int remaining = len;
  assert(rb->head.block && "Head block should never be NULL");

  while (remaining > 0) {
    const char* block_pos = rb->head.block->data + rb->head.index;

    int to_copy;
    if (rb->head.block == rb->tail.block) {
      assert(
          rb->tail.index >= rb->head.index &&
          "Tail index should always be greater than or equal to head index");
      to_copy = rb->tail.index - rb->head.index;
      if (to_copy == 0) {
        assert(initial_size >= rb->size &&
               "The ring buffer size should remain the same or decrease");
        return initial_size - rb->size;
      }
    } else {
      to_copy = UVTLS_RING_BUF_BLOCK_SIZE - rb->head.index;
      if (to_copy == 0) {
        pop_head_block(rb);
        continue;
      }
    }

    if (to_copy > remaining) {
      to_copy = remaining;
    }

    memcpy(pos, block_pos, (unsigned) to_copy);

    rb->head.index += to_copy;
    rb->size -= to_copy;
    pos += to_copy;
    remaining -= to_copy;
  }

  assert(initial_size >= rb->size &&
         "The ring buffer size should remain the same or decrease");
  return initial_size - rb->size;
}

uvtls_ring_buf_pos_t uvtls_ring_buf_head_blocks(const uvtls_ring_buf_t* rb,
                                                uvtls_ring_buf_pos_t pos,
                                                uv_buf_t* bufs,
                                                int* bufs_count) {
  uvtls_ring_buf_pos_t current = pos;
  int count = 0;
  assert(pos.block && "Position block should never be NULL");

  while (count < *bufs_count) {
    uv_buf_t* buf = bufs + count;
    if (current.block == rb->tail.block) {
      int len = rb->tail.index - current.index;
      assert(
          rb->tail.index >= current.index &&
          "Tail index should always be greater than or equal to head index");
      if (len != 0) {
        buf->len = (size_t) len;
        buf->base = current.block->data + current.index;
        count++;
      }
      *bufs_count = count;
      return rb->tail;
    } else {
      int len = UVTLS_RING_BUF_BLOCK_SIZE - current.index;
      if (len != 0) {
        buf->len = (size_t) len;
        buf->base = current.block->data + current.index;
        count++;
      }
    }
    current = uvtls_ring_buf_pos_init(0, current.block->next);
  }
  *bufs_count = count;
  return current;
}

void uvtls_ring_buf_head_blocks_commit(uvtls_ring_buf_t* rb,
                                       uvtls_ring_buf_pos_t pos) {
  while (rb->head.block != pos.block && rb->head.block != rb->tail.block) {
    rb->size -= UVTLS_RING_BUF_BLOCK_SIZE - rb->head.index;
    pop_head_block(rb);
  }
  if (pos.block == rb->tail.block) {
    rb->size -= pos.index - rb->head.index;
  }
  rb->head = pos;
}
