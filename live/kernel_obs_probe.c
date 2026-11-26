/* live probe: load shirudo's kernel-obs upatch on a plain Linux kernel and
 * drain its tables through the upatch's own serializer.
 *
 * This file is deliberately dumb. It attaches the two cgroup_skb programs that
 * carry the net and dns tables, and it calls shirudo_serialize__net and
 * shirudo_serialize__dns exactly the way shirudo's exporter does. Everything
 * that decides what a record says happens in the observer's own BPF code. This
 * program only copies the resulting chunks to disk.
 *
 *   usage: kernel_obs_probe <cgroup-path>
 *   stdin commands:  dump net | dump dns | exit
 *   stdout replies:  ready | done <table> <chunks> | error <why>
 *
 * Chunks land in /tmp/obs/<table>/<seq>/<i>.bin, one 4096-byte serial_chunk per
 * file, in chunk_index order.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define CHUNK_SIZE 4096
#define CHUNK_PAYLOAD 4032
#define MAX_CHUNKS 256
#define SERIAL_MAGIC 0x5a4c5253u
#define SERIAL_DONE (1u << 0)

struct serialize_ctx {
	unsigned int magic;
	unsigned int version;
	unsigned int flags;
	unsigned int max_chunks;
	unsigned int chunk_payload_size;
	unsigned int page_index;
	unsigned long long cursor;
	unsigned long long invocation_id;
};

struct chunk_head {
	unsigned int magic;
	unsigned int version;
	unsigned int flags;
	int status;
	unsigned int chunk_index;
	unsigned int total_chunks;
	unsigned int bytes_total;
	unsigned int bytes_in_chunk;
	unsigned int page_index;
	unsigned int reserved;
	unsigned long long cursor;
	unsigned long long next_cursor;
	unsigned long long invocation_id;
};

static struct bpf_object *obj;
static struct bpf_link *link_egress, *link_ingress;
static int ser_fd = -1;

static int run_syscall_prog(struct bpf_program *prog, void *ctx, size_t ctx_size)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .ctx_in = ctx,
		    .ctx_size_in = ctx ? (unsigned int)ctx_size : 0,
		    .ctx_out = ctx,
		    .ctx_size_out = ctx ? (unsigned int)ctx_size : 0);
	int err = bpf_prog_test_run_opts(bpf_program__fd(prog), &opts);

	if (err)
		return -errno;
	return opts.retval;
}

static unsigned dump_seq;

static int dump_table(const char *table, unsigned max_pages)
{
	char name[64], dir[256], path[320];
	struct bpf_program *prog;
	unsigned int page = 0, total = 0, seq = dump_seq++;
	unsigned long long cursor = 0, next = 0;
	int dirfd_ok;

	snprintf(name, sizeof(name), "shirudo_serialize__%s", table);
	prog = bpf_object__find_program_by_name(obj, name);
	if (!prog) {
		printf("error no-serializer-%s\n", table);
		fflush(stdout);
		return -1;
	}

	snprintf(dir, sizeof(dir), "/tmp/obs/%s/%u", table, seq);
	mkdir("/tmp/obs", 0755);
	snprintf(dir, sizeof(dir), "/tmp/obs/%s", table);
	mkdir(dir, 0755);
	snprintf(dir, sizeof(dir), "/tmp/obs/%s/%u", table, seq);
	dirfd_ok = mkdir(dir, 0755);
	(void)dirfd_ok;

	for (page = 0; page < max_pages; page++) {
		struct serialize_ctx ctx = {
			.magic = SERIAL_MAGIC,
			.version = 1,
			.flags = 0,
			.max_chunks = MAX_CHUNKS,
			.chunk_payload_size = CHUNK_PAYLOAD,
			.page_index = page,
			.cursor = cursor,
			.invocation_id = (unsigned long long)page + 1,
		};
		unsigned int chunk_index, total_chunks = 0;
		int done = 0, ret;

		ret = run_syscall_prog(prog, &ctx, sizeof(ctx));
		if (ret < 0 && ret != -EINVAL) {
			printf("error serialize-%s-%d\n", table, ret);
			fflush(stdout);
			return ret;
		}

		for (chunk_index = 0; chunk_index < MAX_CHUNKS; chunk_index++) {
			unsigned char value[CHUNK_SIZE];
			struct chunk_head head;
			unsigned int key = chunk_index;
			FILE *out;

			if (bpf_map_lookup_elem(ser_fd, &key, value))
				break;
			memcpy(&head, value, sizeof(head));
			if (head.magic != SERIAL_MAGIC)
				break;
			if (head.page_index != page && head.total_chunks == 0)
				break;

			snprintf(path, sizeof(path), "%s/%02u-%03u.bin", dir, page,
				 chunk_index);
			out = fopen(path, "wb");
			if (!out)
				break;
			fwrite(value, 1, CHUNK_SIZE, out);
			fclose(out);
			total++;
			if (head.flags & SERIAL_DONE)
				done = 1;
			next = head.next_cursor;
			total_chunks++;
			if (chunk_index + 1 >= head.total_chunks)
				break;
		}

		if (done || total_chunks == 0)
			break;
		cursor = next;
	}

	mkdir("/tmp/obs", 0755);
	{
		char p[320];
		snprintf(p, sizeof(p), "/tmp/obs/%s/%u/.done", table, seq);
		FILE *f = fopen(p, "w");
		if (f)
			fclose(f);
	}
	printf("done %s %u %u\n", table, seq, total);
	fflush(stdout);
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_program *prog;
	const char *cgroup_path;
	char line[128];
	int cgroup_fd, err;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <cgroup-path> [object]\n", argv[0]);
		return 2;
	}
	cgroup_path = argv[1];

	obj = bpf_object__open_file(argc > 2 ? argv[2] : "kernel-obs.bpf.o", NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "open: %s\n", strerror(-err));
		return 1;
	}

	/* Load only what the net and dns tables need. The rest of the upatch
	 * uses hooks this kernel may not have, and none of it is under test. */
	bpf_object__for_each_program(prog, obj)
		bpf_program__set_autoload(prog, false);
	const char *needed[] = {
		"track_dns_query", "track_dns_response",
		"shirudo_test__kernel_obs",
		"shirudo_serialize__net", "shirudo_serialize__dns",
		/* socket metadata, which is what gives a record its executable */
		"obs_socket_create", "obs_sock_graft", "obs_socket_connect",
	};
	for (unsigned i = 0; i < sizeof(needed) / sizeof(needed[0]); i++) {
		prog = bpf_object__find_program_by_name(obj, needed[i]);
		if (!prog) {
			fprintf(stderr, "missing program %s\n", needed[i]);
			return 1;
		}
		bpf_program__set_autoload(prog, true);
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load: %s\n", strerror(-err));
		return 1;
	}

	ser_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "shirudo_ser"));
	if (ser_fd < 0) {
		fprintf(stderr, "no shirudo_ser map\n");
		return 1;
	}

	/* Sizes every table in the arena: the upatch's own entry point. */
	err = run_syscall_prog(bpf_object__find_program_by_name(
				       obj, "shirudo_test__kernel_obs"), NULL, 0);
	if (err < 0) {
		fprintf(stderr, "init tables: %s\n", strerror(-err));
		return 1;
	}

	cgroup_fd = open(cgroup_path, O_DIRECTORY | O_RDONLY);
	if (cgroup_fd < 0) {
		fprintf(stderr, "cgroup %s: %s\n", cgroup_path, strerror(errno));
		return 1;
	}
	link_egress = bpf_program__attach_cgroup(
		bpf_object__find_program_by_name(obj, "track_dns_query"), cgroup_fd);
	link_ingress = bpf_program__attach_cgroup(
		bpf_object__find_program_by_name(obj, "track_dns_response"), cgroup_fd);
	if (libbpf_get_error(link_egress) || libbpf_get_error(link_ingress)) {
		fprintf(stderr, "attach failed\n");
		return 1;
	}

	printf("ready\n");
	fflush(stdout);

	while (fgets(line, sizeof(line), stdin)) {
		char table[32];
		if (sscanf(line, "dump1 %31s", table) == 1) {
			dump_table(table, 1);
		} else if (sscanf(line, "dump %31s", table) == 1) {
			dump_table(table, 256);
		} else if (!strncmp(line, "exit", 4)) {
			break;
		}
	}
	return 0;
}
