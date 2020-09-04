/*
 * Copyright (C) 2013 Daniel Mack <daniel@zonque.org>
 * Modified by Yu Mi <yxm319@case.edu>.
 * Bloom filter implementation.
 * See https://en.wikipedia.org/wiki/Bloom_filter
 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/hash.h>
#include <linux/kref.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>

#include "bloom_filter.h"

#define _BLOOM_FILTER_UNIT_TEST_
#undef _BLOOM_FILTER_UNIT_TEST_

struct bloom_crypto_alg{
	__u8					*data;
	__u16					order; // the order of this crypto algorithm
	__u32					len;
	bool					hash_tfm_allocated;
	bool					is_dummy;

	struct crypto_hash		*hash_tfm;
	struct list_head		node;
};

/** bloom_filter_create - create a bloom filter instance
 * @bitsize: the length of bloom filter
 */
struct bloom_filter * bloom_filter_create(__u32 bitsize)
{
	struct bloom_filter *filter;
	__u32 i = 0, ret = 0;
	__u32 bitmap_size = bitsize%32 ? (bitsize>>5) + 1 : (bitsize>>5);

	filter = kzalloc(sizeof(struct bloom_filter) + bitmap_size, GFP_KERNEL);
	if(!filter)
		return ERR_PTR(-ENOMEM);

	kref_init(&filter->ref_count);
	filter->bitmap_size = bitsize;
	filter->bitmap_bytes = bitmap_size;
	filter->num_algs = 0;
	INIT_LIST_HEAD(&(filter->alg_list));

#ifdef _BLOOM_FILTER_UNIT_TEST_
	printk(KERN_INFO "Bloom filter initialized at %p.\n", filter);
#endif /* _BLOOM_FILTER_UNIT_TEST_ */

	return filter;
}

/** bloom_filter_create_n - create a bloom filter instance with n hash functions
 * @bitsize: the length of bloom filter
 * @num_algs: requested number of algorithms
 */
struct bloom_filter * bloom_filter_create_n(__u32 bitsize, __u32 num_algs)
{
	struct bloom_filter *filter;
	__u32 i = 0, ret = 0;
	__u32 bitmap_size = bitsize%32 ? (bitsize>>5) + 1 : (bitsize>>5);

	filter = kzalloc(sizeof(struct bloom_filter) + bitmap_size, GFP_KERNEL);
	if(!filter)
		return ERR_PTR(-ENOMEM);

	kref_init(&filter->ref_count);
	filter->bitmap_size = bitsize;
	filter->bitmap_bytes = bitmap_size;
	filter->num_algs = num_algs;
	INIT_LIST_HEAD(&(filter->alg_list));

	for(i = 0; i< num_algs; i++){
		switch (i){
		case 0:
			ret = bloom_filter_add_hash_alg(filter, "sha1");
			break;
		case 1:
			ret = bloom_filter_add_hash_alg(filter, "md5");
			break;
		default:
			ret = bloom_filter_add_hash_alg(filter, "dummy");
			break;
		}
		if(ret < 0){
			printk(KERN_WARNING "Error creating hash function NO.=%d.\n", i);
			return ERR_PTR(ret);
		}
	}
#ifdef _BLOOM_FILTER_UNIT_TEST_
	printk(KERN_INFO "Bloom filter initialized at %p.\n", filter);
#endif /* _BLOOM_FILTER_UNIT_TEST_ */
	return filter;
}

/** bloom_filter_add_hash_alg - add a hash algorithm to this bloom filter
 * @filter: the filter to add hash algorithm
 * @name: the name of hash funtcion
 */
int bloom_filter_add_hash_alg(struct bloom_filter *filter, const char *name)
{
	struct bloom_crypto_alg *alg, *last;
	int ret = 0;
	char name_dummy[] = "dummy";

	alg = kzalloc(sizeof(struct bloom_crypto_alg), GFP_KERNEL);
	if(!alg){
		ret = -ENOMEM;
		goto exit;
	}

	if(memcmp(name_dummy, name, sizeof(name_dummy))){ // is not dummy
		alg->is_dummy = false;
	}
	else{
		alg->is_dummy = true;
		goto is_dummy_out;
	}

	alg->hash_tfm = crypto_alloc_hash(name, 0, CRYPTO_ALG_ASYNC);
	if(IS_ERR(alg->hash_tfm)){
		ret = PTR_ERR(alg->hash_tfm);
		goto err_create_tfm;
	}

	alg->hash_tfm_allocated = true;
	alg->len = crypto_hash_digestsize(alg->hash_tfm);
	alg->data = kzalloc(alg->len, GFP_KERNEL);
	if(!alg->data){
		ret = -ENOMEM;
		goto err_create_data;
	}
	
	if(list_is_singular(&(filter->alg_list))){
		alg->order = 1;
	}
	else{
		last = list_last_entry(&(filter->alg_list), struct bloom_crypto_alg, node);
		alg->order = last->order + 1;
	}

	list_add_tail(&(alg->node), &(filter->alg_list));

	filter->num_algs ++;

	return 0;

is_dummy_out:

	if(list_is_singular(&(filter->alg_list))){
		alg->order = 1;
	}
	else{
		last = list_last_entry(&(filter->alg_list), struct bloom_crypto_alg, node);
		alg->order = last->order + 1;
	}

	list_add_tail(&(alg->node), &(filter->alg_list));

	filter->num_algs ++;

	return 0;

err_create_data:
	crypto_free_hash(alg->hash_tfm);

err_create_tfm:
	kfree(alg);

exit:
	return ret;
}

/** bloom_filter_add_crypto_hash - add a cryptologic hash instance to this bloom filter
 * @filter: the filter to add hash 
 * @hash_tfm: crypto hash transform instance
 */
int bloom_filter_add_crypto_hash(struct bloom_filter *filter, struct crypto_hash *hash_tfm)
{
	struct bloom_crypto_alg *alg, *last;
	__u32 ret = 0;

	alg = kzalloc(sizeof(struct bloom_crypto_alg), GFP_KERNEL);
	if(!alg){
		ret = -ENOMEM;
		goto exit;
	}

	alg->len = crypto_hash_digestsize(hash_tfm);
	alg->is_dummy = false;
	alg->data = kzalloc(alg->len, GFP_KERNEL);
	if(!alg->data){
		ret = -ENOMEM;
		goto err_create_data;
	}

	if(list_is_singular(&filter->alg_list)){
		alg->order = 1;
	}
	else{
		last = list_last_entry(&filter->alg_list, struct bloom_crypto_alg, node);
		alg->order = last->order + 1;
	}

	list_add_tail(&alg->node, &filter->alg_list);

	filter->num_algs ++;

	return 0;

err_create_data:
	kfree(alg);

exit:
	return ret;
}
/** __bit_for_crypto_alg -- generate a bit position from hashing algorithm
 * @alg: the hash algorithm
 * @sg: scatter list for memory mapping hashing data
 * @wrap_size: the bitmap size for us to wrap around
 * @bit: the returning bit position
 */
int __bit_for_crypto_alg(struct bloom_crypto_alg *alg,
						 struct scatterlist *sg,
						__u32 wrap_size,
						__u32 *bit)
{
	struct hash_desc desc;
	__u32 i, temp;
	int ret;

#ifdef _BLOOM_FILTER_UNIT_TEST_
	printk(KERN_INFO "Wrap_size = %d.\n", wrap_size);
#endif /* _BLOOM_FILTER_UNIT_TEST_ */

	/** NOTE: originally we may use CRYPTO_TRM_REQ_MAY_SLEEP, 
	 * but we want this process to be non-blocking. */
	desc.flags = CRYPTO_TFM_REQ_MAY_BACKLOG; 
	desc.tfm = alg->hash_tfm;

	ret = crypto_hash_init(&desc);
	if (ret < 0){
		return ret;
	}

	/** NOTE: could be error here: 3rd parameter should be length of data*/
	ret = crypto_hash_digest(&desc, sg, sg->length, alg->data);
	if (ret < 0){
		return ret;
	}

	temp = 0;
	for(i = 0; i<alg->len; i++)
	{
#ifdef _BLOOM_FILTER_UNIT_TEST_
		printk("%02x ", alg->data[i]);
#endif /* _BLOOM_FILTER_UNIT_TEST_*/
		if(i < 3){
			continue;
		}
		temp += (alg->data[i-3]<<24 + \
				alg->data[i-2]<<16 + \
				alg->data[i-1]<<8 + \
				alg->data[i]);

		temp %= wrap_size;
	}

#ifdef _BLOOM_FILTER_UNIT_TEST_
	printk("\n %d\n", temp);
#endif /* _BLOOM_FILTER_UNIT_TEST_ */
	*bit = temp;

	return 0;
}

/** bloom_filter_insert - insert an element into the filter
 * @filter: the bloom filter instance to be inserted
 * @data: the starting pointer for data structure
 * @size: the length of data structure
 */
int bloom_filter_insert(struct bloom_filter *filter, const __u8 *data, __u32 size)
{
	struct bloom_crypto_alg *alg;
	struct scatterlist sg;
	int ret = 0;
	__u32 count = 0;
	__u32 bit1 = 0, bit2 = 0;
	bool bit1_hashed = false, bit2_hashed = false;

	if (list_empty(&(filter->alg_list))){
		ret = -EINVAL;
		goto exit;
	}

	sg_init_one(&sg, data, size);

	list_for_each_entry(alg, &filter->alg_list, node){// We may not use list operations or change the dummy into lists
		__u32 bit;
		count ++;
		if(alg->is_dummy){
			bit = (bit1 + (alg->order) * bit2) % filter->bitmap_size;
		}
		else{
			if(!bit1_hashed){
				ret = __bit_for_crypto_alg(alg, &sg, filter->bitmap_size, &bit);
				bit1 = bit;
				bit1_hashed = true;
			}
			else if (!bit2_hashed){
				ret = __bit_for_crypto_alg(alg, &sg, filter->bitmap_size, &bit);
				bit2 = bit;
				bit2_hashed = true;
			}
			else{
				ret = __bit_for_crypto_alg(alg, &sg, filter->bitmap_size, &bit);
			}
		}
#ifdef _BLOOM_FILTER_UNIT_TEST_
		printk(KERN_INFO "Inserting bit pos=%d %d.\n", bit, count);
#endif /* _BLOOM_FILTER_UNIT_TEST_ */
		if(ret < 0){
			goto exit;
		}

		set_bit(bit, filter->bitmap);
	}

exit:
	return ret;
}

/** bloom_filter_check - checks if an element is in the filter
 * @filter: the bloom filter to check
 * @data: the starting pointer for data structure
 * @size: the length of data structure,
 * @result: the result pointer for output
 */
int bloom_filter_check(struct bloom_filter *filter, const __u8 *data, __u32 size, bool * result)
{
	struct bloom_crypto_alg *alg;
	struct scatterlist sg;
	int ret = 0;
	__u32 bit1 = 0, bit2 = 0, count = 0;
	bool bit1_hashed = false, bit2_hashed = false;

	if(list_empty(&filter->alg_list)){
		ret = -EINVAL;
		goto exit;
	}

	sg_init_one(&sg, data, size);

	*result = true;

	list_for_each_entry(alg, &filter->alg_list, node){
		__u32 bit;
		count ++;
		if(alg->is_dummy){
			bit = (bit1 + (alg->order) * bit2) % filter->bitmap_size;
		}
		else{
			if(!bit1_hashed){
				ret = __bit_for_crypto_alg(alg, &sg, filter->bitmap_size, &bit);
				bit1 = bit;
				bit1_hashed = true;
			}
			else if (!bit2_hashed){
				ret = __bit_for_crypto_alg(alg, &sg, filter->bitmap_size, &bit);
				bit2 = bit;
				bit2_hashed = true;
			}
			else{
				ret = __bit_for_crypto_alg(alg, &sg, filter->bitmap_size, &bit);
			}
		}
#ifdef _BLOOM_FILTER_UNIT_TEST_
		printk(KERN_INFO "Checking bit pos=%d %d.\n", bit, count);
#endif /* _BLOOM_FILTER_UNIT_TEST_ */
		if(ret < 0){
			goto exit;
		}

		if (!test_bit(bit, filter->bitmap)){
			*result = false;
			break;
		}
	}

exit:
	return ret;
}

/** bloom_filter_ref - records a reference for bloom filter
 * @filter: the bloom filter to be referenced
 */
void bloom_filter_ref(struct bloom_filter *filter)
{
	kref_get(&filter->ref_count);
}

/** bloom_crypto_alg_free - free a registered crypto alg
 * @alg: the algorithm struct to be freed
 */
static void bloom_crypto_alg_free(struct bloom_crypto_alg *alg)
{
	if(alg->hash_tfm_allocated)
		crypto_free_hash(alg->hash_tfm);

	list_del(&alg->node);

	kfree(alg->data);
	kfree(alg);
}

/** __bloom_filter_free - free a bloom filter from reference
 * @kref: the referecne to call this free
 */
static void __bloom_filter_free(struct kref *kref)
{
	struct bloom_crypto_alg *alg, *tmp;
	struct bloom_filter *filter = container_of(kref, struct bloom_filter, ref_count);

	list_for_each_entry_safe(alg, tmp, &filter->alg_list, node)
		bloom_crypto_alg_free(alg);

	kfree(filter);
#ifdef _BLOOM_FILTER_UNIT_TEST_
	printk(KERN_WARNING "Bloom filter destroyed.\n");
#endif /* _BLOOM_FILTER_UNIT_TEST_ */
}

/** bloom_filter_unref - removes a reference for bloom filter, 
 * free the filter is not used anymore
 * @filter: the bloom filter to be unreferenced
 */
void bloom_filter_unref(struct bloom_filter *filter)
{
	kref_put(&filter->ref_count, __bloom_filter_free);
}

/** bloom_filter_set - set the bitmap in a bloom filter
 * @filter: the filter to be set
 * @data: the bitmap to set
 */
void bloom_filter_bitmap_set(struct bloom_filter *filter, const __u8 *data)
{
	memcpy(filter->bitmap, data, filter->bitmap_bytes);
}

/** bloom_filter_bitmap_clear - clear the bitmap in a bloom filter
 * @filter: the filter to be cleared
 */
void bloom_filter_bitmap_clear(struct bloom_filter *filter)
{
	if(filter->bitmap) // Only clear available bitmaps
		bitmap_zero(filter->bitmap, filter->bitmap_size);
}

/** bloom_filter_get_hash_digest - get a hash digest for input scatterlist
 * NOTE: the data is put into the algorithm's data element
 * @alg: the hash algorithm
 * @data: the data to be hashed
 * @size: the size of data
 */
int __bloom_filter_get_hash_digest(struct bloom_crypto_alg * alg,
								   const __u8 *data,
								   __u32 size)
{
	struct hash_desc desc;
	struct scatterlist sg;
	__u32 i, temp;
	int ret;

	sg_init_one(&sg, data, size);

	desc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	desc.tfm = alg->hash_tfm;

	ret = crypto_hash_init(&desc);
	if (ret < 0){
		return ret;
	}

	ret = crypto_hash_digest(&desc, &sg, sg.length, alg->data);

	if (ret < 0){
		return ret;
	}

	return 0;
}

/** bloom_filter_print_each_hash_digest - print hash digest for each algorithm
 * @filter: the bloom filter
 * @data: the data to compute hash digest
 * @size: the size of data
 */
int bloom_filter_print_each_hash_digest(struct bloom_filter *filter, const __u8 *data, __u32 size)
{
	struct bloom_crypto_alg *alg;
	int ret;
	__u32 i;

	list_for_each_entry(alg, &(filter->alg_list), node){
		ret = __bloom_filter_get_hash_digest(alg, data, size);
		if (ret < 0){
			return ret;
		}

		for(i = 0; i < alg->len; i++){
			printk("%02x ", alg->data[i]);
		}
		printk("\n");
	}
}

#ifdef _BLOOM_FILTER_UNIT_TEST_
int run_testing(void){

	struct bloom_filter * filter = bloom_filter_create(1024);
	char str1[] = "name_balabala";
	char str2[] = "hash_longlonglonglonglong";
	char str3[] = "function_is_fully_working!";
	bool result = true;
	int ret;

	printk(KERN_WARNING "Testing hash function:\n");
	ret = bloom_filter_add_hash_alg(filter, "sha1");
	if (ret < 0){
		printk(KERN_WARNING "Adding sha1 failed.\n");
		return ret;
	}

	ret = bloom_filter_add_hash_alg(filter, "md5");
	if (ret < 0){
		printk(KERN_WARNING "Adding md5 failed.\n");
		return ret;
	}

	ret = bloom_filter_print_each_hash_digest(filter, str1, sizeof(str1) -1);
	if(ret < 0){
		printk(KERN_WARNING "Error computing hash");
		return ret;
	}
	else{
		printk(KERN_INFO "Correct answer reference:\n");
		printk(KERN_INFO "a3 a3 5b 22 74 8f db 76 7b b8 92 ee 59 c7 d4 05 53 27 3c ff\n");
		printk(KERN_INFO "ea 04 99 f2 be 7a 2a 82 4c a2 0f ec 01 1c bf 3b\n");
	}
	bloom_filter_unref(filter);

	printk(KERN_WARNING "Testing inserting function:\n");
	filter = bloom_filter_create_n(15000000, 5);

	ret = bloom_filter_insert(filter, str1, sizeof(str1) - 1);
	if (ret < 0){
		printk(KERN_INFO "Inserting \"%s\" error.\n", str1);
		return ret;
	}

	ret = bloom_filter_insert(filter, str2, sizeof(str2) - 1);
	if (ret < 0){
		printk(KERN_INFO "Inserting \"s\" error.\n", str2);
		return ret;
	}

	ret = bloom_filter_check(filter, str3, sizeof(str3) - 1, &result);
	if (ret < 0){
		printk(KERN_INFO "Checking entry for \"%s\" error. \n", str3);
		return ret;
	}
	else{
		printk(KERN_INFO "Checking entry, should be 0, result is %d\n", result);
	}

	ret = bloom_filter_check(filter, str1, sizeof(str1) -1, &result);
	if (ret < 0){
		printk(KERN_INFO "Checking entry for \"%s\" error. \n", str3);
		return ret;
	}
	else{
		printk(KERN_INFO "Checking entry, should be 1, result is %d\n", result);
	}

	bloom_filter_unref(filter);
	return ret;
}


static int __init lkm_test_init(void) {
	printk(KERN_INFO "Testing module loaded.\n");
	run_testing();
	return 0;
}

static void __exit lkm_test_exit(void) {

	printk(KERN_INFO "Testing module exited.\n");
}

module_init(lkm_test_init);
module_exit(lkm_test_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yu Mi");
MODULE_DESCRIPTION("Testing module");
MODULE_VERSION("1");
#endif /* _BLOOM_FILTER_UNIT_TEST_ */