#include <uvtls/ringbuffer.h>

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static uvtls_ringbuffer_pos_t pos_init(uvtls_ringbuffer_block_t *block,
                                       int index) {
  uvtls_ringbuffer_pos_t pos;
  pos.block = block;
  pos.index = index;
  return pos;
}

static void free_blocks(uvtls_ringbuffer_block_t *blocks) {
  uvtls_ringbuffer_block_t *current = blocks;
  while (current) {
    uvtls_ringbuffer_block_t *next = current->next;
    free(current);
    current = next;
  }
}

static uvtls_ringbuffer_block_t *create_block() {
  uvtls_ringbuffer_block_t *block =
      (uvtls_ringbuffer_block_t *)malloc(sizeof(uvtls_ringbuffer_block_t));
  block->next = NULL;
  return block;
}

static void push_tail_block(uvtls_ringbuffer_t *rb) {
  if (rb->empty_blocks) {
    uvtls_ringbuffer_block_t *empty_block = rb->empty_blocks;
    rb->tail.block->next = empty_block;
    rb->empty_blocks = empty_block->next;
    empty_block->next = NULL;
  } else {
    rb->tail.block->next = create_block();
  }
  rb->tail.block = rb->tail.block->next;
  rb->tail.index = 0;
}

static void pop_head_block(uvtls_ringbuffer_t *rb) {
  uvtls_ringbuffer_block_t *empty_block = rb->empty_blocks;
  uvtls_ringbuffer_block_t *head_block = rb->head.block;
  rb->empty_blocks = head_block;
  rb->head.block = head_block->next;
  head_block->next = empty_block;
  rb->head.index = 0;
}

void uvtls_ringbuffer_init(uvtls_ringbuffer_t *rb) {
  rb->empty_blocks = NULL;
  rb->head = rb->tail =
      (uvtls_ringbuffer_pos_t){.index = 0, .block = create_block()};
  rb->size = 0;
  rb->ret = -1;
}

void uvtls_ringbuffer_destroy(uvtls_ringbuffer_t *rb) {
  free_blocks(rb->empty_blocks);
  free_blocks(rb->head.block);
}

int uvtls_ringbuffer_size(const uvtls_ringbuffer_t *rb) { return rb->size; }

void uvtls_ringbuffer_reset(uvtls_ringbuffer_t *rb) {
  while (rb->head.block != rb->tail.block) {
    pop_head_block(rb);
  }
  rb->head.index = rb->tail.index = 0;
  rb->size = 0;
}

void uvtls_ringbuffer_write(uvtls_ringbuffer_t *rb, const char *data,
                            int size) {
  assert(rb->tail.block && "Tail block should never be NULL");
  const char *pos = data;
  int remaining = size;

  while (remaining > 0) {
    assert(rb->tail.index <= UVTLS_RING_BUFFER_BLOCK_SIZE &&
           "Tail index should always be less than or equal to block size");
    int to_copy = UVTLS_RING_BUFFER_BLOCK_SIZE - rb->tail.index;

    if (to_copy == 0) {
      push_tail_block(rb);
      to_copy = UVTLS_RING_BUFFER_BLOCK_SIZE;
    }

    if (to_copy > remaining) {
      to_copy = remaining;
    }

    memcpy(rb->tail.block->data + rb->tail.index, pos, (unsigned)to_copy);

    rb->tail.index += to_copy;
    rb->size += to_copy;
    pos += to_copy;
    remaining -= to_copy;
  }
}

int uvtls_ringbuffer_tail_block(uvtls_ringbuffer_t *rb, char **data, int size) {
  assert(rb->tail.block && "Tail block should never be NULL");
  assert(rb->tail.index <= UVTLS_RING_BUFFER_BLOCK_SIZE &&
         "Tail index should always be less than or equal to block size");
  int available = UVTLS_RING_BUFFER_BLOCK_SIZE - rb->tail.index;

  if (available == 0) {
    push_tail_block(rb);
    available = UVTLS_RING_BUFFER_BLOCK_SIZE;
  }

  *data = rb->tail.block->data + rb->tail.index;

  return size > available ? available : size;
}

void uvtls_ringbuffer_tail_block_commit(uvtls_ringbuffer_t *rb, int size) {
  assert(rb->tail.block && "Tail block should never be NULL");
  int available = UVTLS_RING_BUFFER_BLOCK_SIZE - rb->tail.index;
  int to_commit = size;
  if (to_commit > available) {
    to_commit = available;
  }
  rb->tail.index += to_commit;
  rb->size += to_commit;
  assert(rb->tail.index <= UVTLS_RING_BUFFER_BLOCK_SIZE &&
         "Tail index should always be less than or equal to block size");
}

int uvtls_ringbuffer_read(uvtls_ringbuffer_t *rb, char *data, int len) {
  assert(rb->head.block && "Head block should never be NULL");
  int initial_size = rb->size;
  char *pos = data;
  int remaining = len;

  while (remaining > 0) {
    const char *block_pos = rb->head.block->data + rb->head.index;

    int to_copy;
    if (rb->head.block == rb->tail.block) {
      assert(rb->tail.index >= rb->head.index &&
             "Tail index should always be greater than or equal to head index");
      to_copy = rb->tail.index - rb->head.index;
      if (to_copy == 0) {
        assert(initial_size >= rb->size &&
               "The ring buffer size should remain the same or decrease");
        return initial_size - rb->size;
      }
    } else {
      to_copy = UVTLS_RING_BUFFER_BLOCK_SIZE - rb->head.index;
      if (to_copy == 0) {
        pop_head_block(rb);
        continue;
      }
    }

    if (to_copy > remaining) {
      to_copy = remaining;
    }

    memcpy(pos, block_pos, (unsigned)to_copy);

    rb->head.index += to_copy;
    rb->size -= to_copy;
    pos += to_copy;
    remaining -= to_copy;
  }

  assert(initial_size >= rb->size &&
         "The ring buffer size should remain the same or decrease");
  return initial_size - rb->size;
}

uvtls_ringbuffer_pos_t
uvtls_ringbuffer_head_blocks(const uvtls_ringbuffer_t *rb,
                             uvtls_ringbuffer_pos_t pos, uv_buf_t *bufs,
                             int *bufs_count) {
  assert(pos.block && "Position block should never be NULL");

  uvtls_ringbuffer_pos_t current = pos;
  int count = 0;

  while (count < *bufs_count) {
    uv_buf_t *buf = bufs + count;
    if (current.block == rb->tail.block) {
      assert(rb->tail.index >= current.index &&
             "Tail index should always be greater than or equal to head index");
      int len = rb->tail.index - current.index;
      if (len != 0) {
        buf->len = (size_t)len;
        buf->base = current.block->data + current.index;
        count++;
      }
      *bufs_count = count;
      return rb->tail;
    } else {
      int len = UVTLS_RING_BUFFER_BLOCK_SIZE - current.index;
      if (len != 0) {
        buf->len = (size_t)len;
        buf->base = current.block->data + current.index;
        count++;
      }
    }
    current = pos_init(current.block->next, 0);
  }
  *bufs_count = count;
  return current;
}

void uvtls_ringbuffer_head_blocks_commit(uvtls_ringbuffer_t *rb,
                                         uvtls_ringbuffer_pos_t pos) {
  while (rb->head.block != pos.block && rb->head.block != rb->tail.block) {
    pop_head_block(rb);
  }
  rb->head = pos;
}
