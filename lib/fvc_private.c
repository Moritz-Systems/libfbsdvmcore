/*-
 * Copyright (c) 1989, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software developed by the Computer Systems
 * Engineering group at Lawrence Berkeley Laboratory under DARPA contract
 * BG 91-66 and contributed to Berkeley.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>

#include <sys/stat.h>
#include <sys/mman.h>

#include <stdbool.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <nlist.h>
#include <paths.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <inttypes.h>

#include "fvc.h"
#include "fvc_private.h"

/*
 * Routines private to libfvc.
 */

/*
 * Report an error using printf style arguments.  "program" is kd->program
 * on hard errors, and 0 on soft errors, so that under sun error emulation,
 * only hard errors are printed out (otherwise, programs like gdb will
 * generate tons of error messages when trying to access bogus pointers).
 */
void
_fvc_err(fvc_t *kd, const char *program, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (program != NULL) {
		(void)fprintf(stderr, "%s: ", program);
		(void)vfprintf(stderr, fmt, ap);
		(void)fputc('\n', stderr);
	} else
		(void)vsnprintf(kd->errbuf,
		    sizeof(kd->errbuf), fmt, ap);

	va_end(ap);
}

void
_fvc_syserr(fvc_t *kd, const char *program, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	if (program != NULL) {
		(void)fprintf(stderr, "%s: ", program);
		(void)vfprintf(stderr, fmt, ap);
		(void)fprintf(stderr, ": %s\n", strerror(errno));
	} else {
		char *cp = kd->errbuf;

		(void)vsnprintf(cp, sizeof(kd->errbuf), fmt, ap);
		n = strlen(cp);
		(void)snprintf(&cp[n], sizeof(kd->errbuf) - n, ": %s",
		    strerror(errno));
	}
	va_end(ap);
}

void *
_fvc_malloc(fvc_t *kd, size_t n)
{
	void *p;

	if ((p = calloc(n, sizeof(char))) == NULL)
		_fvc_err(kd, kd->program, "can't allocate %zu bytes: %s",
			 n, strerror(errno));
	return (p);
}

int
_fvc_probe_elf_kernel(fvc_t *kd, int class, int machine)
{

	return (kd->nlehdr.e_ident[EI_CLASS] == class &&
	    ((machine == EM_PPC || machine == EM_PPC64) ?
	     kd->nlehdr.e_type == ET_DYN : kd->nlehdr.e_type == ET_EXEC) &&
	    kd->nlehdr.e_machine == machine);
}

int
_fvc_is_minidump(fvc_t *kd)
{
	char minihdr[8];

	if (pread(kd->pmfd, &minihdr, 8, 0) == 8 &&
	    memcmp(&minihdr, "minidump", 8) == 0)
		return (1);
	return (0);
}

/*
 * The powerpc backend has a hack to strip a leading kerneldump
 * header from the core before treating it as an ELF header.
 *
 * We can add that here if we can get a change to libelf to support
 * an initial offset into the file.  Alternatively we could patch
 * savecore to extract cores from a regular file instead.
 */
int
_fvc_read_core_phdrs(fvc_t *kd, size_t *phnump, GElf_Phdr **phdrp)
{
	GElf_Ehdr ehdr;
	GElf_Phdr *phdr;
	Elf *elf;
	size_t i, phnum;

	elf = elf_begin(kd->pmfd, ELF_C_READ, NULL);
	if (elf == NULL) {
		_fvc_err(kd, kd->program, "%s", elf_errmsg(0));
		return (-1);
	}
	if (elf_kind(elf) != ELF_K_ELF) {
		_fvc_err(kd, kd->program, "invalid core");
		goto bad;
	}
	if (gelf_getclass(elf) != kd->nlehdr.e_ident[EI_CLASS]) {
		_fvc_err(kd, kd->program, "invalid core");
		goto bad;
	}
	if (gelf_getehdr(elf, &ehdr) == NULL) {
		_fvc_err(kd, kd->program, "%s", elf_errmsg(0));
		goto bad;
	}
	if (ehdr.e_type != ET_CORE) {
		_fvc_err(kd, kd->program, "invalid core");
		goto bad;
	}
	if (ehdr.e_machine != kd->nlehdr.e_machine) {
		_fvc_err(kd, kd->program, "invalid core");
		goto bad;
	}

	if (elf_getphdrnum(elf, &phnum) == -1) {
		_fvc_err(kd, kd->program, "%s", elf_errmsg(0));
		goto bad;
	}

	phdr = calloc(phnum, sizeof(*phdr));
	if (phdr == NULL) {
		_fvc_err(kd, kd->program, "failed to allocate phdrs");
		goto bad;
	}

	for (i = 0; i < phnum; i++) {
		if (gelf_getphdr(elf, i, &phdr[i]) == NULL) {
			free(phdr);
			_fvc_err(kd, kd->program, "%s", elf_errmsg(0));
			goto bad;
		}
	}
	elf_end(elf);
	*phnump = phnum;
	*phdrp = phdr;
	return (0);

bad:
	elf_end(elf);
	return (-1);
}

/*
 * Transform v such that only bits [bit0, bitN) may be set.  Generates a
 * bitmask covering the number of bits, then shifts so +bit0+ is the first.
 */
static uint64_t
bitmask_range(uint64_t v, uint64_t bit0, uint64_t bitN)
{
	if (bit0 == 0 && bitN == BITS_IN(v))
		return (v);

	return (v & (((1ULL << (bitN - bit0)) - 1ULL) << bit0));
}

/*
 * Returns the number of bits in a given byte array range starting at a
 * given base, from bit0 to bitN.  bit0 may be non-zero in the case of
 * counting backwards from bitN.
 */
static uint64_t
popcount_bytes(uint64_t *addr, uint32_t bit0, uint32_t bitN)
{
	uint32_t res = bitN - bit0;
	uint64_t count = 0;
	uint32_t bound;

	/* Align to 64-bit boundary on the left side if needed. */
	if ((bit0 % BITS_IN(*addr)) != 0) {
		bound = MIN(bitN, fvc_roundup2(bit0, BITS_IN(*addr)));
		count += __builtin_popcountll(bitmask_range(*addr, bit0, bound));
		res -= (bound - bit0);
		addr++;
	}

	while (res > 0) {
		bound = MIN(res, BITS_IN(*addr));
		count += __builtin_popcountll(bitmask_range(*addr, 0, bound));
		res -= bound;
		addr++;
	}

	return (count);
}

void *
_fvc_pmap_get(fvc_t *kd, u_long idx, size_t len)
{
	uintptr_t off = idx * len;

	if ((off_t)off >= kd->pt_sparse_off)
		return (NULL);
	return (void *)((uintptr_t)kd->page_map + off);
}

void *
_fvc_map_get(fvc_t *kd, u_long pa, unsigned int page_size)
{
	off_t off;
	uintptr_t addr;

	off = _fvc_pt_find(kd, pa, page_size);
	if (off == -1)
		return NULL;

	addr = (uintptr_t)kd->page_map + off;
	if (off >= kd->pt_sparse_off)
		addr = (uintptr_t)kd->sparse_map + (off - kd->pt_sparse_off);
	return (void *)addr;
}

int
_fvc_pt_init(fvc_t *kd, size_t dump_avail_size, off_t dump_avail_off,
    size_t map_len, off_t map_off, off_t sparse_off, int page_size)
{
	uint64_t *addr;
	uint32_t *popcount_bin;
	int bin_popcounts = 0;
	uint64_t pc_bins, res;
	ssize_t rd;

	kd->dump_avail_size = dump_avail_size;
	if (dump_avail_size > 0) {
		kd->dump_avail = mmap(NULL, kd->dump_avail_size, PROT_READ,
		    MAP_PRIVATE, kd->pmfd, dump_avail_off);
	} else {
		/*
		 * Older version minidumps don't provide dump_avail[],
		 * so the bitmap is fully populated from 0 to
		 * last_pa. Create an implied dump_avail that
		 * expresses this.
		 */
		kd->dump_avail = calloc(4, sizeof(uint64_t));
		kd->dump_avail[1] = _fvc64toh(kd, map_len * 8 * page_size);
	}

	/*
	 * Map the bitmap specified by the arguments.
	 */
	kd->pt_map = _fvc_malloc(kd, map_len);
	if (kd->pt_map == NULL) {
		_fvc_err(kd, kd->program, "cannot allocate %zu bytes for bitmap",
		    map_len);
		return (-1);
	}
	rd = pread(kd->pmfd, kd->pt_map, map_len, map_off);
	if (rd < 0 || rd != (ssize_t)map_len) {
		_fvc_err(kd, kd->program, "cannot read %zu bytes for bitmap",
		    map_len);
		return (-1);
	}
	kd->pt_map_size = map_len;

	/*
	 * Generate a popcount cache for every POPCOUNT_BITS in the bitmap,
	 * so lookups only have to calculate the number of bits set between
	 * a cache point and their bit.  This reduces lookups to O(1),
	 * without significantly increasing memory requirements.
	 *
	 * Round up the number of bins so that 'upper half' lookups work for
	 * the final bin, if needed.  The first popcount is 0, since no bits
	 * precede bit 0, so add 1 for that also.  Without this, extra work
	 * would be needed to handle the first PTEs in _fvc_pt_find().
	 */
	addr = kd->pt_map;
	res = map_len;
	pc_bins = 1 + (res * NBBY + POPCOUNT_BITS / 2) / POPCOUNT_BITS;
	kd->pt_popcounts = calloc(pc_bins, sizeof(uint32_t));
	if (kd->pt_popcounts == NULL) {
		_fvc_err(kd, kd->program, "cannot allocate popcount bins");
		return (-1);
	}

	for (popcount_bin = &kd->pt_popcounts[1]; res > 0;
	    addr++, res -= sizeof(*addr)) {
		*popcount_bin += popcount_bytes(addr, 0,
		    MIN(res * NBBY, BITS_IN(*addr)));
		if (++bin_popcounts == POPCOUNTS_IN(*addr)) {
			popcount_bin++;
			*popcount_bin = *(popcount_bin - 1);
			bin_popcounts = 0;
		}
	}

	assert(pc_bins * sizeof(*popcount_bin) ==
	    ((uintptr_t)popcount_bin - (uintptr_t)kd->pt_popcounts));

	kd->pt_sparse_off = sparse_off;
	kd->pt_sparse_size = (uint64_t)*popcount_bin * page_size;
	kd->pt_page_size = page_size;

	/*
	 * Map the sparse page array.  This is useful for performing point
	 * lookups of specific pages, e.g. for fvc_walk_pages.  Generally,
	 * this is much larger than is reasonable to read in up front, so
	 * mmap it in instead.
	 */
	kd->sparse_map = mmap(NULL, kd->pt_sparse_size, PROT_READ,
	    MAP_PRIVATE, kd->pmfd, kd->pt_sparse_off);
	if (kd->sparse_map == MAP_FAILED) {
		_fvc_err(kd, kd->program, "cannot map %" PRIu64
		    " bytes from fd %d offset %jd for sparse map: %s",
		    kd->pt_sparse_size, kd->pmfd,
		    (intmax_t)kd->pt_sparse_off, strerror(errno));
		return (-1);
	}
	return (0);
}

int
_fvc_pmap_init(fvc_t *kd, uint32_t pmap_size, off_t pmap_off)
{
	ssize_t exp_len = pmap_size;

	kd->page_map_size = pmap_size;
	kd->page_map_off = pmap_off;
	kd->page_map = _fvc_malloc(kd, pmap_size);
	if (kd->page_map == NULL) {
		_fvc_err(kd, kd->program, "cannot allocate %u bytes "
		    "for page map", pmap_size);
		return (-1);
	}
	if (pread(kd->pmfd, kd->page_map, pmap_size, pmap_off) != exp_len) {
		_fvc_err(kd, kd->program, "cannot read %d bytes from "
		    "offset %jd for page map", pmap_size, (intmax_t)pmap_off);
		return (-1);
	}
	return (0);
}

static inline uint64_t
dump_avail_n(fvc_t *kd, long i)
{
	return (_fvc64toh(kd, kd->dump_avail[i]));
}

uint64_t
_fvc_pa_bit_id(fvc_t *kd, uint64_t pa, unsigned int page_size)
{
	uint64_t adj;
	long i;

	adj = 0;
	for (i = 0; dump_avail_n(kd, i + 1) != 0; i += 2) {
		if (pa >= dump_avail_n(kd, i + 1)) {
			adj += howmany(dump_avail_n(kd, i + 1), page_size) -
			    dump_avail_n(kd, i) / page_size;
		} else {
			return (pa / page_size -
			    dump_avail_n(kd, i) / page_size + adj);
		}
	}
	return (_FVC_BIT_ID_INVALID);
}

uint64_t
_fvc_bit_id_pa(fvc_t *kd, uint64_t bit_id, unsigned int page_size)
{
	uint64_t sz;
	long i;

	for (i = 0; dump_avail_n(kd, i + 1) != 0; i += 2) {
		sz = howmany(dump_avail_n(kd, i + 1), page_size) -
		    dump_avail_n(kd, i) / page_size;
		if (bit_id < sz) {
			return (fvc_rounddown2(dump_avail_n(kd, i), page_size) +
			    bit_id * page_size);
		}
		bit_id -= sz;
	}
	return (_FVC_PA_INVALID);
}

/*
 * Find the offset for the given physical page address; returns -1 otherwise.
 *
 * A page's offset is represented by the sparse page base offset plus the
 * number of bits set before its bit multiplied by page size.  This means
 * that if a page exists in the dump, it's necessary to know how many pages
 * in the dump precede it.  Reduce this O(n) counting to O(1) by caching the
 * number of bits set at POPCOUNT_BITS intervals.
 *
 * Then to find the number of pages before the requested address, simply
 * index into the cache and count the number of bits set between that cache
 * bin and the page's bit.  Halve the number of bytes that have to be
 * checked by also counting down from the next higher bin if it's closer.
 */
off_t
_fvc_pt_find(fvc_t *kd, uint64_t pa, unsigned int page_size)
{
	uint64_t *bitmap = kd->pt_map;
	uint64_t pte_bit_id = _fvc_pa_bit_id(kd, pa, page_size);
	uint64_t pte_u64 = pte_bit_id / BITS_IN(*bitmap);
	uint64_t popcount_id = pte_bit_id / POPCOUNT_BITS;
	uint64_t pte_mask = 1ULL << (pte_bit_id % BITS_IN(*bitmap));
	uint64_t bitN;
	uint32_t count;

	/* Check whether the page address requested is in the dump. */
	if (pte_bit_id == _FVC_BIT_ID_INVALID ||
	    pte_bit_id >= (kd->pt_map_size * NBBY) ||
	    (bitmap[pte_u64] & pte_mask) == 0)
		return (-1);

	/*
	 * Add/sub popcounts from the bitmap until the PTE's bit is reached.
	 * For bits that are in the upper half between the calculated
	 * popcount id and the next one, use the next one and subtract to
	 * minimize the number of popcounts required.
	 */
	if ((pte_bit_id % POPCOUNT_BITS) < (POPCOUNT_BITS / 2)) {
		count = kd->pt_popcounts[popcount_id] + popcount_bytes(
		    bitmap + popcount_id * POPCOUNTS_IN(*bitmap),
		    0, pte_bit_id - popcount_id * POPCOUNT_BITS);
	} else {
		/*
		 * Counting in reverse is trickier, since we must avoid
		 * reading from bytes that are not in range, and invert.
		 */
		uint64_t pte_u64_bit_off = pte_u64 * BITS_IN(*bitmap);

		popcount_id++;
		bitN = MIN(popcount_id * POPCOUNT_BITS,
		    kd->pt_map_size * BITS_IN(uint8_t));
		count = kd->pt_popcounts[popcount_id] - popcount_bytes(
		    bitmap + pte_u64,
		    pte_bit_id - pte_u64_bit_off, bitN - pte_u64_bit_off);
	}

	/*
	 * This can only happen if the core is truncated.  Treat these
	 * entries as if they don't exist, since their backing doesn't.
	 */
	if (count >= (kd->pt_sparse_size / page_size))
		return (-1);

	return (kd->pt_sparse_off + (uint64_t)count * page_size);
}

static int
fvc_fdnlist(fvc_t *kd, struct fvc_nlist *list)
{
	fvc_addr_t addr;
	int error, nfail;

	nfail = 0;
	while (list->n_name != NULL && list->n_name[0] != '\0') {
		error = kd->resolve_symbol(list->n_name, &addr,
		    kd->resolve_symbol_data);
		if (error != 0) {
			nfail++;
			list->n_value = 0;
		} else
			list->n_value = addr;
		list++;
	}
	return (nfail);
}

int
_fvc_nlist(fvc_t *kd, struct fvc_nlist *nl)
{

	return fvc_fdnlist(kd, nl);
}

int
_fvc_bitmap_init(struct fvc_bitmap *bm, u_long bitmapsize, u_long *idx)
{

	*idx = ULONG_MAX;
	bm->map = calloc(bitmapsize, sizeof *bm->map);
	if (bm->map == NULL)
		return (0);
	bm->size = bitmapsize;
	return (1);
}

void
_fvc_bitmap_set(struct fvc_bitmap *bm, u_long bm_index)
{
	uint8_t *byte = &bm->map[bm_index / 8];

	if (bm_index / 8 < bm->size)
		*byte |= (1UL << (bm_index % 8));
}

int
_fvc_bitmap_next(struct fvc_bitmap *bm, u_long *idx)
{
	u_long first_invalid = bm->size * CHAR_BIT;

	if (*idx == ULONG_MAX)
		*idx = 0;
	else
		(*idx)++;

	/* Find the next valid idx. */
	for (; *idx < first_invalid; (*idx)++) {
		unsigned int mask = 1U << (*idx % CHAR_BIT);
		if ((bm->map[*idx / CHAR_BIT] & mask) != 0)
			break;
	}

	return (*idx < first_invalid);
}

void
_fvc_bitmap_deinit(struct fvc_bitmap *bm)
{

	free(bm->map);
}

int
_fvc_visit_cb(fvc_t *kd, fvc_walk_pages_cb_t *cb, void *arg, u_long pa,
    u_long kmap_vaddr, u_long dmap_vaddr, fvc_vm_prot_t prot, size_t len,
    unsigned int page_size)
{
	unsigned int pgsz = page_size ? page_size : len;
	struct fvc_page p = {
		.kp_version = LIBFVC_WALK_PAGES_VERSION,
		.kp_paddr = pa,
		.kp_kmap_vaddr = kmap_vaddr,
		.kp_dmap_vaddr = dmap_vaddr,
		.kp_prot = prot,
		.kp_offset = _fvc_pt_find(kd, pa, pgsz),
		.kp_len = len,
	};

	return cb(&p, arg);
}

int
_fvc_libelf_resolver(const char *name, fvc_addr_t *addr, void *data)
{
	struct fvc_libelf_resolver_data *r_data = data;
	size_t sh_index, sh_num;

	if (elf_getshdrnum(r_data->elf, &sh_num) != 0)
		return (-1);

	for (sh_index = 1; sh_index < sh_num; sh_index++) {
		Elf_Scn *scn;
		GElf_Shdr shdr_mem, *shdr;
		Elf_Data *data = NULL;

		scn = elf_getscn(r_data->elf, sh_index);
		if (scn == NULL)
			continue;
		shdr = gelf_getshdr(scn, &shdr_mem);
		if (shdr == NULL)
			continue;
		if (shdr->sh_type != SHT_SYMTAB)
			continue;

		while ((data = elf_getdata(scn, data))) {
			size_t count = shdr->sh_size / shdr->sh_entsize;
			size_t i;

			for (i = 0; i < count; i++) {
				GElf_Sym sym_mem, *sym;
				const char *symbol_name;

				sym = gelf_getsym(data, i, &sym_mem);
				if (!sym)
					continue;
				symbol_name = elf_strptr(r_data->elf,
				    shdr->sh_link, sym->st_name);

				if (!strcmp(symbol_name, name)) {
					*addr = sym->st_value;
					return (0);
				}
			}
		}
	}

	return (-1);
}

int
_fvc_libelf_resolver_data_init(fvc_t *kd, const char *path)
{
	const size_t data_len = sizeof(struct fvc_libelf_resolver_data);
	struct fvc_libelf_resolver_data *r_data;

	kd->resolve_symbol_data = _fvc_malloc(kd, data_len);
	if (kd->resolve_symbol_data == NULL) {
		_fvc_err(kd, kd->program, "cannot allocate %zu bytes for "
		    "resolver data", data_len);
		return (-1);
	}

	r_data = kd->resolve_symbol_data;
	if ((r_data->fd = open(path, O_RDONLY | O_CLOEXEC, 0)) < 0) {
		_fvc_syserr(kd, kd->program, "%s", path);
		free(kd->resolve_symbol_data);
		return (-1);
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		_fvc_err(kd, kd->program, "Unsupported libelf");
		close(r_data->fd);
		free(kd->resolve_symbol_data);
		return (-1);
	}
	r_data->elf = elf_begin(r_data->fd, ELF_C_READ, NULL);
	if (r_data->elf == NULL) {
		_fvc_err(kd, kd->program, "%s", elf_errmsg(0));
		close(r_data->fd);
		free(kd->resolve_symbol_data);
		return (-1);
	}

	return (0);
}

void
_fvc_libelf_resolver_data_deinit(fvc_t *kd)
{
	struct fvc_libelf_resolver_data *r_data = kd->resolve_symbol_data;

	elf_end(r_data->elf);
	close(r_data->fd);
	free(kd->resolve_symbol_data);
}
