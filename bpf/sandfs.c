/*
 * This module has the kernel code for SandFS
 */
#define KBUILD_MODNAME "sandfs"
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

#include <linux/version.h>
#include <linux/fs.h>

#include <linux/sandfs.h>

/********************************************************************
	HELPERS
*********************************************************************/
#define PRINTK(fmt, ...)                                               \
                ({                                                      \
                        char ____fmt[] = fmt;                           \
                        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                                     ##__VA_ARGS__);                    \
                })

#define DEBUG

#ifdef DEBUG
#define DBG PRINTK
#else
#define DBG(fmt, ...)
#endif

#define ERR PRINTK

#define PATH_MAX_SUPP 256

struct bpf_map_def SEC("maps") datamap = {
		.type			= BPF_MAP_TYPE_HASH,	// simple hash list
		.key_size 		= PATH_MAX_SUPP,
		.value_size 	= sizeof(int),
        .max_entries 	= 32,
};

static int get_path(void *ctx, char *path)
{
	int ret = -1;
	struct sandfs_args *args = (struct sandfs_args *)ctx;
	uint32_t opcode = args->op;

	uint32_t len;
	ret = bpf_sandfs_read_args(ctx, PARAM_0_SIZE, &len, sizeof(u32));
	if (ret) {
		ERR("op %d: failed to read path len: %d!\n", opcode, ret);
	} else {
		if (PATH_MAX_SUPP < len) {
			ERR("op %d: not enough memory!\n", opcode);
			ret = -E2BIG;
		} else {
			ret = bpf_sandfs_read_args(ctx, PARAM_0_VALUE, path, PATH_MAX_SUPP);
			if (ret) {
				ERR("LOOKUP: failed to read path: %d!\n", ret);
			} else {
				ret = 0;
			}
		}
	}

	return ret;
}

static int sandfs_lookup(void *ctx)
{
	char path[PATH_MAX_SUPP] = {0};
	int ret = get_path(ctx, path);
	if (!ret) {
		DBG("SANDFS_LOOKUP(%s)\n", path);
		int *val = bpf_map_lookup_elem(&datamap, path);
		if (val) {
			DBG("SANDFS_LOOKUP(%s): denied\n", path);
			ret = *val;
		}
	}
	return ret;
}

static int sandfs_open(void *ctx)
{
	return 0;
}

static int sandfs_read(void *ctx)
{
	char path[PATH_MAX_SUPP] = {0};
	int ret = get_path(ctx, path);
	if (!ret) {
		DBG("SANDFS_READ(%s)\n", path);
	}
	return ret;
}

static int sandfs_write(void *ctx)
{
	char path[PATH_MAX_SUPP] = {0};
	int ret = get_path(ctx, path);
	if (!ret) {
		DBG("SANDFS_READ(%s)\n", path);
	}
	return ret;
}

static int sandfs_close(void *ctx)
{
	return 0;
}

/*
 * SandFS main handler function
 */
int SEC("sandfs") sandfs_main_handler(void *ctx)
{
	int ret = 0;
	struct sandfs_args *args = (struct sandfs_args *)ctx;
	uint32_t opcode = args->op;
	DBG("opcode %d\n", opcode);
	if (opcode == SANDFS_LOOKUP)
		ret = sandfs_lookup(ctx);
	else if (opcode == SANDFS_OPEN)
		ret = sandfs_open(ctx);
	else if (opcode == SANDFS_READ)
		ret = sandfs_read(ctx);
	else if (opcode == SANDFS_WRITE)
		ret = sandfs_write(ctx);
	else if (opcode == SANDFS_CLOSE)
		ret = sandfs_close(ctx);
	return ret;
}

char _license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = LINUX_VERSION_CODE;

