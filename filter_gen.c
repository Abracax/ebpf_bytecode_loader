#include "filter_gen.h"

static struct bpf_elf_sec_data data;
static int bpf_elf_ctx_init(struct bpf_elf_ctx *ctx, const char *obj);
static int bpf_load_license(struct bpf_elf_ctx *ctx);
static void bpf_fetch_load_prog(struct bpf_elf_ctx *ctx, const char *section);

static int bpf_fill_section_data(struct bpf_elf_ctx *ctx, int section,
								 struct bpf_elf_sec_data *data)
{
	Elf_Data *sec_edata;
	GElf_Shdr sec_hdr;
	Elf_Scn *sec_fd;
	char *sec_name;

	memset(data, 0, sizeof(*data));

	sec_fd = elf_getscn(ctx->elf_fd, section);
	if (!sec_fd)
		return -1;
	if (gelf_getshdr(sec_fd, &sec_hdr) != &sec_hdr)
		return -1;

	sec_name = elf_strptr(ctx->elf_fd, ctx->elf_hdr.e_shstrndx,
						  sec_hdr.sh_name);
	if (!sec_name || !sec_hdr.sh_size)
		return -1;

	sec_edata = elf_getdata(sec_fd, NULL);
	if (!sec_edata || elf_getdata(sec_fd, sec_edata))
		return -1;

	memcpy(&data->sec_hdr, &sec_hdr, sizeof(sec_hdr));

	data->sec_name = sec_name;
	data->sec_data = sec_edata;
	return 0;
}

static int bpf_load_license(struct bpf_elf_ctx *ctx)
{
	int i, ret = -1;

	for (i = 1; i < ctx->elf_hdr.e_shnum; i++)
	{
		ret = bpf_fill_section_data(ctx, i, &data);
		if (ret < 0)
			continue;

		if (data.sec_hdr.sh_type == SHT_PROGBITS &&
			!strcmp(data.sec_name, "license"))
		{
			memcpy(ctx->license, data.sec_data->d_buf, data.sec_data->d_size);
			return 0;
		}
	}
	return ret;
}

static int bpf_elf_ctx_init(struct bpf_elf_ctx *ctx, const char *obj)
{
	if (elf_version(EV_CURRENT) == EV_NONE)
		return -EINVAL;

	int ret = 0;

	struct rlimit limit = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	setrlimit(RLIMIT_MEMLOCK, &limit);

	memset(ctx, 0, sizeof(*ctx));

	ctx->obj_fd = open(obj, O_RDWR, 0666);
	if (ctx->obj_fd < 0)
		return ctx->obj_fd;

	ctx->elf_fd = elf_begin(ctx->obj_fd, ELF_C_READ, NULL);

	if (!ctx->elf_fd)
	{
		ret = -EINVAL;
		printf("Fail to retrieve elf fd\n");
		goto out_fd;
	}

	if (gelf_getehdr(ctx->elf_fd, &ctx->elf_hdr) !=
		&ctx->elf_hdr)
	{
		printf("elf header err\n");
		ret = -EIO;
		goto out_elf;
	}

	return ret;

out_elf:
	elf_end(ctx->elf_fd);
out_fd:
	close(ctx->obj_fd);

	return ret;
}

static void bpf_fetch_load_prog(struct bpf_elf_ctx *ctx, const char *section)
{
	int i, ret = -1;

	for (i = 1; i < ctx->elf_hdr.e_shnum; i++)
	{
		ret = bpf_fill_section_data(ctx, i, &data);
		if (ret < 0)
			continue;

		if (strcmp(data.sec_name, section))
			continue;

		int filter_len = data.sec_data->d_size / sizeof(struct bpfinstr);

		struct bpfinstr *filter_out = data.sec_data->d_buf;
		printf("\ninstruction stream:\n{\n");
		for (i = 0; i < filter_len; i++)
		{
			printf("    {0x%x, 0x%x, 0x%x, 0x%x}, \n", filter_out[i].code, filter_out[i].jt, filter_out[i].jf, filter_out[i].k);
		}
		printf("};\n\n");

		printf("number of instructions: %d\n", filter_len);
		break;
	}
}

void generate_hex_dump(char *file_name, char *section_name)
{
	int ret = -1;
	struct bpf_elf_ctx __ctx;
	ret = bpf_elf_ctx_init(&__ctx, file_name);
	ret = bpf_load_license(&__ctx);

	if (ret < 0)
	{
		fprintf(stderr, "Cannot initialize ELF context!\n");
	}

	bpf_fetch_load_prog(&__ctx, section_name);
}
