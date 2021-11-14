/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1992, 1993
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
 *
 *	@(#)fvc_private.h	8.1 (Berkeley) 6/4/93
 * $FreeBSD$
 */

#include "config.h"

#ifdef HAVE_SYS_ENDIAN_H
#	include <sys/endian.h>
#endif
#ifdef HAVE_ENDIAN_H
#	include <endian.h>
#endif

#include <gelf.h>

struct fvc_nlist {
	const char *n_name;
	unsigned char n_type;
	fvc_addr_t n_value;
};

struct fvc_arch {
	int	(*ka_probe)(fvc_t *);
	int	(*ka_initvtop)(fvc_t *);
	void	(*ka_freevtop)(fvc_t *);
	int	(*ka_kvatop)(fvc_t *, fvc_addr_t, off_t *);
	int	(*ka_walk_pages)(fvc_t *, fvc_walk_pages_cb_t *, void *);
	ssize_t (*ka_kerndisp)(fvc_t *);
};

struct __fvc {
	struct fvc_arch *arch;
	/*
	 * a string to be prepended to error messages
	 * provided for compatibility with sun's interface
	 * if this value is null, errors are saved in errbuf[]
	 */
	const char *program;
	char	*errp;		/* XXX this can probably go away */
	char	errbuf[_POSIX2_LINE_MAX];
	int	pmfd;		/* physical memory file (or crashdump) */
	int	nlfd;		/* namelist file (e.g., /kernel) */
	GElf_Ehdr nlehdr;	/* ELF file header for namelist file */
	int	(*resolve_symbol)(const char *, fvc_addr_t *, void *);
	void	*resolve_symbol_data;
	/*
	 * Kernel virtual address translation state.  This only gets filled
	 * in for dead kernels; otherwise, the running kernel (i.e. kmem)
	 * will do the translations for us.  It could be big, so we
	 * only allocate it if necessary.
	 */
	struct vmstate *vmst;

	/* Page table lookup structures. */
	uint64_t	*pt_map;
	size_t		pt_map_size;
	uint64_t	*dump_avail;	/* actually word sized */
	size_t		dump_avail_size;
	off_t		pt_sparse_off;
	uint64_t	pt_sparse_size;
	uint32_t	*pt_popcounts;
	unsigned int	pt_page_size;

	/* Page & sparse map structures. */
	void		*page_map;
	uint32_t	page_map_size;
	off_t		page_map_off;
	void		*sparse_map;
};

struct fvc_bitmap {
	uint8_t *map;
	u_long size;
};

struct fvc_libelf_resolver_data {
	int	fd;
	Elf	*elf;
};

/* Page table lookup constants. */
#define POPCOUNT_BITS	1024
#define BITS_IN(v)	(sizeof(v) * NBBY)
#define POPCOUNTS_IN(v)	(POPCOUNT_BITS / BITS_IN(v))

/*
 * Functions used internally by fvc, but across fvc modules.
 */
static inline uint16_t
_fvc16toh(fvc_t *kd, uint16_t val)
{

	if (kd->nlehdr.e_ident[EI_DATA] == ELFDATA2LSB)
		return (le16toh(val));
	else
		return (be16toh(val));
}

static inline uint32_t
_fvc32toh(fvc_t *kd, uint32_t val)
{

	if (kd->nlehdr.e_ident[EI_DATA] == ELFDATA2LSB)
		return (le32toh(val));
	else
		return (be32toh(val));
}

static inline uint64_t
_fvc64toh(fvc_t *kd, uint64_t val)
{

	if (kd->nlehdr.e_ident[EI_DATA] == ELFDATA2LSB)
		return (le64toh(val));
	else
		return (be64toh(val));
}

uint64_t _fvc_pa_bit_id(fvc_t *kd, uint64_t pa, unsigned int page_size);
uint64_t _fvc_bit_id_pa(fvc_t *kd, uint64_t bit_id, unsigned int page_size);
#define _FVC_PA_INVALID		ULONG_MAX
#define _FVC_BIT_ID_INVALID	ULONG_MAX

int	 _fvc_bitmap_init(struct fvc_bitmap *, u_long, u_long *);
void	 _fvc_bitmap_set(struct fvc_bitmap *, u_long);
int	 _fvc_bitmap_next(struct fvc_bitmap *, u_long *);
void	 _fvc_bitmap_deinit(struct fvc_bitmap *);

void	 _fvc_err(fvc_t *kd, const char *program, const char *fmt, ...)
	    __attribute__((format(printf, 3, 4)));
void	*_fvc_malloc(fvc_t *kd, size_t);
int	 _fvc_nlist(fvc_t *, struct fvc_nlist *);
void	 _fvc_syserr (fvc_t *kd, const char *program, const char *fmt, ...)
	    __attribute__((format(printf, 3, 4)));
int	 _fvc_probe_elf_kernel(fvc_t *, int, int);
int	 _fvc_is_minidump(fvc_t *);
int	 _fvc_read_core_phdrs(fvc_t *, size_t *, GElf_Phdr **);
int	 _fvc_pt_init(fvc_t *, size_t, off_t, size_t, off_t, off_t, int);
off_t	 _fvc_pt_find(fvc_t *, uint64_t, unsigned int);
int	 _fvc_visit_cb(fvc_t *, fvc_walk_pages_cb_t *, void *, u_long,
	    u_long, u_long, vm_prot_t, size_t, unsigned int);
int	 _fvc_pmap_init(fvc_t *, uint32_t, off_t);
void *	 _fvc_pmap_get(fvc_t *, u_long, size_t);
void *	 _fvc_map_get(fvc_t *, u_long, unsigned int);

int	 _fvc_libelf_resolver(const char *, fvc_addr_t *, void *);
int	 _fvc_libelf_resolver_data_init(fvc_t *, const char *);
void	 _fvc_libelf_resolver_data_deinit(fvc_t *);
