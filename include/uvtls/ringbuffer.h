#ifndef UVTLS_RINGBUFFER_H
#define UVTLS_RINGBUFFER_H

#include <uv.h>

#define UVTLS_RING_BUFFER_BLOCK_SIZE (16 * 1014 + 5)

typedef struct uvtls_ringbuffer_s uvtls_ringbuffer_t;
typedef struct uvtls_ringbuffer_block_s uvtls_ringbuffer_block_t;
typedef struct uvtls_ringbuffer_position_s uvtls_ringbuffer_position_t;

struct uvtls_ringbuffer_position_s {
  int index;
  uvtls_ringbuffer_block_t *block;
};

struct uvtls_ringbuffer_s {
  uvtls_ringbuffer_position_t tail;
  uvtls_ringbuffer_position_t head;
  uvtls_ringbuffer_block_t *empty_blocks;
  int size;
  int ret;
};

struct uvtls_ringbuffer_block_s {
  char data[UVTLS_RING_BUFFER_BLOCK_SIZE];
  uvtls_ringbuffer_block_t *next;
};

void uvtls_ringbuffer_init(uvtls_ringbuffer_t *rb);

void uvtls_ringbuffer_destroy(uvtls_ringbuffer_t *rb);

int uvtls_ringbuffer_size(const uvtls_ringbuffer_t *rb);

void uvtls_ringbuffer_reset(uvtls_ringbuffer_t *rb);

void uvtls_ringbuffer_write(uvtls_ringbuffer_t *rb, const char *data, int size);

int uvtls_ringbuffer_tail_block(uvtls_ringbuffer_t *rb, char **data, int size);

void uvtls_ringbuffer_tail_block_commit(uvtls_ringbuffer_t *rb, int size);

int uvtls_ringbuffer_read(uvtls_ringbuffer_t *rb, char *data, int len);

int uvtls_ringbuffer_head_blocks(const uvtls_ringbuffer_t *rb, uv_buf_t *bufs,
                                 int bufs_count);

int uvtls_ringbuffer_head_blocks_commit(uvtls_ringbuffer_t *rb, int size);

#endif /* UVTLS_RINGBUFFER_H */
