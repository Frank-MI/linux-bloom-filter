/**
 * Code Modified by Yu Mi to implement the bloom filter to filter out packets,
 * reference include:
 * https://github.com/zonque/linux-bloom-filter/
 * https://www.eecs.harvard.edu/~michaelm/postscripts/tr-02-05.pdf
 */

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
	__u32					*bitmap;
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
int bloom_filter_hamming_weight(struct bloom_filter *filter, __u32 *weight);

#ifndef _BLOOM_MURMUR32_
#define _BLOOM_MURMUR32_
/** murmur32_hash - the murmurhash function
 * @data: the data starting pointer
 * @len: the length of data in bytes
 * @seed: the initial value of hash
 */
__u32 murmur32_hash(const void *data, int len, __u32 seed){
	__u32 rotl32(__u32 var, __u32 hops){
		return (var << hops) | (var >> (32-hops));
	}
	const __u32 c1 = 0xcc9e2d51;
	const __u32 c2 = 0x1b873593;
	const __u32 nblocks = len / 4;
	__u32 h1 = seed, k1 = 0;
	int i = 0;

	const __u8 * _data = (const __u8 *) data;
	const __u32 * blocks = (const __u32 *) (_data + nblocks*4);

	for(i = -nblocks; i; i++){
		k1 = blocks[i];

		k1 *= c1;
		k1 = rotl32(k1, 15);
		k1 *= c2;

		h1 ^= k1;
		h1 = rotl32(h1, 13);
		h1 = h1 * 5 + 0xe6546b64;
	}

	const __u8 * tail = (const __u8 *) (_data + nblocks*4);
	k1 = 0;

	switch(len & 0x03){
		case 3: k1 ^= tail[2] << 16;
		case 2: k1 ^= tail[1] << 8;
		case 1: k1 ^= tail[0];
				k1 *= c1; k1 = rotl32(k1, 15); k1 *= c2; h1 ^= k1;
	};

	h1 ^= len;

	h1 ^= h1 >> 16;
	h1 *= 0x85ebca6b;
	h1 ^= h1 >> 13;
	h1 *= 0xc2b2ae35;
	h1 ^= h1 >> 16;

	return h1;
}
#endif /* BLOOM_MURMUR32_ */
#endif /* _BLOOM_FILTER_H_ */
