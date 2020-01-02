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
