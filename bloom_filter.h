
#ifndef _BLOOM_FILTER_H_
#define _BLOOM_FILTER_H_
#include <crypto/algapi.h>
#include <crypto/hash.h>

struct bloom_filter {
	struct kref				ref_count;

	struct list_head		alg_list;
	__u32					num_algs;
	__u32					bitmap_size;
	__u32					bitmap_bytes;
	__u32					bitmap[0];
};

/** Creating and disassembling function */
struct bloom_filter * bloom_filter_create(__u32 bitsize);
struct bloom_filter * bloom_filter_create_n(__u32 bitsize, __u32 num_algs);
void bloom_filter_ref(struct bloom_filter *filter);
void bloom_filter_unref(struct bloom_filter *filter);

/** Configuring hash functions */
int bloom_filter_add_crypto_hash(struct bloom_filter *filter, struct crypto_hash *hash_tfm);
int bloom_filter_add_hash_alg(struct bloom_filter *filter, const char *name);

/** Managing bloom bitmap*/
void bloom_filter_bitmap_clear(struct bloom_filter *filter);
void bloom_filter_bitmap_set(struct bloom_filter *filter, const __u8 *data);

/** Inserting or checking bloom filter */
int bloom_filter_insert(struct bloom_filter *filter, const __u8 *data, __u32 size);
int bloom_filter_check(struct bloom_filter *filter, const __u8 *data, __u32 size, bool * result);

/** Auxiliary function */
int bloom_filter_print_each_hash_digest(struct bloom_filter *filter, const __u8 *data, __u32 size);
#endif /* _BLOOM_FILTER_H_ */
