#ifndef __FILTER_GEN_H__
#define __FILTER_GEN_H__

#include <gelf.h>
#include <libelf.h>
#include <libgen.h>

#include <asm/types.h>

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/pkt_cls.h>

#include <sys/resource.h>
#include <sys/syscall.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define ELF_MAX_MAPS 64
#define ELF_MAX_LICENSE_LEN 128

extern void generate_hex_dump(char *file_name, char *section_name);

struct bpfinstr
{
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
};

static inline __u64 bpf_ptr_to_u64(const void *ptr)
{
    return (__u64)(unsigned long)ptr;
}

struct bpf_elf_sec_data
{
    GElf_Shdr sec_hdr;
    Elf_Data *sec_data;
    const char *sec_name;
};

struct bpf_elf_st
{
    dev_t st_dev;
    ino_t st_ino;
};

struct bpf_config
{
    unsigned int jit_enabled;
};

struct bpf_elf_map
{
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

struct bpf_prog_data
{
    unsigned int type;
    unsigned int jited;
};

struct bpf_map_ext
{
    struct bpf_prog_data owner;
    unsigned int btf_id_key;
    unsigned int btf_id_val;
};

struct bpf_elf_prog
{
    enum bpf_prog_type type;
    struct bpf_insn *insns;
    unsigned int insns_num;
    size_t size;
    const char *license;
};

struct bpf_btf
{
    const struct btf_header *hdr;
    const void *raw;
    const char *strings;
    const struct btf_type **types;
    int types_num;
};

struct bpf_elf_ctx
{
    struct bpf_config cfg;
    Elf *elf_fd;
    GElf_Ehdr elf_hdr;
    Elf_Data *sym_tab;
    Elf_Data *str_tab;
    Elf_Data *btf_data;
    char obj_uid[64];
    int obj_fd;
    int btf_fd;
    int map_fds[ELF_MAX_MAPS];
    struct bpf_elf_map maps[ELF_MAX_MAPS];
    struct bpf_map_ext maps_ext[ELF_MAX_MAPS];
    struct bpf_elf_prog prog_text;
    struct bpf_btf btf;
    int sym_num;
    int map_num;
    int map_len;
    bool *sec_done;
    int sec_maps;
    int sec_text;
    int sec_btf;
    char license[ELF_MAX_LICENSE_LEN];
    enum bpf_prog_type type;
    __u32 ifindex;
    bool verbose;
    bool noafalg;
    struct bpf_elf_st stat;
    struct bpf_hash_entry *ht[256];
    char *log;
    size_t log_size;
};

#endif