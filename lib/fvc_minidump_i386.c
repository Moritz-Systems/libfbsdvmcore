/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2006 Peter Wemm
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * i386 machine dependent routines for fvc and minidumps.
 */

#include <sys/param.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "minidump/i386.h"

#include <limits.h>

#include "fvc.h"
#include "fvc_private.h"
#include "fvc_i386.h"

#define	i386_round_page(x)	fvc_roundup2((fvc_addr_t)(x), I386_PAGE_SIZE)

struct vmstate {
	struct minidumphdr hdr;
};

static i386_pte_pae_t
_i386_pte_pae_get(fvc_t *kd, u_long pteindex)
{
	i386_pte_pae_t *pte = _fvc_pmap_get(kd, pteindex, sizeof(*pte));

	return le64toh(*pte);
}

static i386_pte_t
_i386_pte_get(fvc_t *kd, u_long pteindex)
{
	i386_pte_t *pte = _fvc_pmap_get(kd, pteindex, sizeof(*pte));

	return le32toh(*pte);
}

static int
_i386_minidump_probe(fvc_t *kd)
{

	return (_fvc_probe_elf_kernel(kd, ELFCLASS32, EM_386) &&
	    _fvc_is_minidump(kd));
}

static void
_i386_minidump_freevtop(fvc_t *kd)
{
	struct vmstate *vm = kd->vmst;

	free(vm);
	kd->vmst = NULL;
}

static int
_i386_minidump_initvtop(fvc_t *kd)
{
	struct vmstate *vmst;
	off_t off, dump_avail_off, sparse_off;

	vmst = _fvc_malloc(kd, sizeof(*vmst));
	if (vmst == NULL) {
		_fvc_err(kd, kd->program, "cannot allocate vm");
		return (-1);
	}
	kd->vmst = vmst;
	if (pread(kd->pmfd, &vmst->hdr, sizeof(vmst->hdr), 0) !=
	    sizeof(vmst->hdr)) {
		_fvc_err(kd, kd->program, "cannot read dump header");
		return (-1);
	}
	if (strncmp(MINIDUMP_MAGIC, vmst->hdr.magic, sizeof(vmst->hdr.magic)) != 0) {
		_fvc_err(kd, kd->program, "not a minidump for this platform");
		return (-1);
	}
	vmst->hdr.version = le32toh(vmst->hdr.version);
	if (vmst->hdr.version != MINIDUMP_VERSION && vmst->hdr.version != 1) {
		_fvc_err(kd, kd->program, "wrong minidump version. expected %d got %d",
		    MINIDUMP_VERSION, vmst->hdr.version);
		return (-1);
	}
	vmst->hdr.msgbufsize = le32toh(vmst->hdr.msgbufsize);
	vmst->hdr.bitmapsize = le32toh(vmst->hdr.bitmapsize);
	vmst->hdr.ptesize = le32toh(vmst->hdr.ptesize);
	vmst->hdr.kernbase = le32toh(vmst->hdr.kernbase);
	vmst->hdr.paemode = le32toh(vmst->hdr.paemode);
	vmst->hdr.dumpavailsize = vmst->hdr.version == MINIDUMP_VERSION ?
	    le32toh(vmst->hdr.dumpavailsize) : 0;

	/* Skip header and msgbuf */
	dump_avail_off = I386_PAGE_SIZE + i386_round_page(vmst->hdr.msgbufsize);

	/* Skip dump_avail */
	off = dump_avail_off + i386_round_page(vmst->hdr.dumpavailsize);

	sparse_off = off + i386_round_page(vmst->hdr.bitmapsize) +
	    i386_round_page(vmst->hdr.ptesize);
	if (_fvc_pt_init(kd, vmst->hdr.dumpavailsize, dump_avail_off,
	    vmst->hdr.bitmapsize, off, sparse_off, I386_PAGE_SIZE) == -1) {
		return (-1);
	}
	off += i386_round_page(vmst->hdr.bitmapsize);

	if (_fvc_pmap_init(kd, vmst->hdr.ptesize, off) == -1) {
		return (-1);
	}
	off += i386_round_page(vmst->hdr.ptesize);

	return (0);
}

static int
_i386_minidump_vatop_pae(fvc_t *kd, fvc_addr_t va, off_t *pa)
{
	struct vmstate *vm;
	i386_physaddr_pae_t offset;
	i386_pte_pae_t pte;
	fvc_addr_t pteindex;
	i386_physaddr_pae_t a;
	off_t ofs;

	vm = kd->vmst;
	offset = va & I386_PAGE_MASK;

	if (va >= vm->hdr.kernbase) {
		pteindex = (va - vm->hdr.kernbase) >> I386_PAGE_SHIFT;
		if (pteindex >= vm->hdr.ptesize / sizeof(pte))
			goto invalid;
		pte = _i386_pte_pae_get(kd, pteindex);
		if ((pte & I386_PG_V) == 0) {
			_fvc_err(kd, kd->program,
			    "_i386_minidump_vatop_pae: pte not valid");
			goto invalid;
		}
		a = pte & I386_PG_FRAME_PAE;
		ofs = _fvc_pt_find(kd, a, I386_PAGE_SIZE);
		if (ofs == -1) {
			_fvc_err(kd, kd->program,
	    "_i386_minidump_vatop_pae: physical address 0x%jx not in minidump",
			    (uintmax_t)a);
			goto invalid;
		}
		*pa = ofs + offset;
		return (I386_PAGE_SIZE - offset);
	} else {
		_fvc_err(kd, kd->program,
	    "_i386_minidump_vatop_pae: virtual address 0x%jx not minidumped",
		    (uintmax_t)va);
		goto invalid;
	}

invalid:
	_fvc_err(kd, 0, "invalid address (0x%jx)", (uintmax_t)va);
	return (0);
}

static int
_i386_minidump_vatop(fvc_t *kd, fvc_addr_t va, off_t *pa)
{
	struct vmstate *vm;
	i386_physaddr_t offset;
	i386_pte_t pte;
	fvc_addr_t pteindex;
	i386_physaddr_t a;
	off_t ofs;

	vm = kd->vmst;
	offset = va & I386_PAGE_MASK;

	if (va >= vm->hdr.kernbase) {
		pteindex = (va - vm->hdr.kernbase) >> I386_PAGE_SHIFT;
		if (pteindex >= vm->hdr.ptesize / sizeof(pte))
			goto invalid;
		pte = _i386_pte_get(kd, pteindex);
		if ((pte & I386_PG_V) == 0) {
			_fvc_err(kd, kd->program,
			    "_i386_minidump_vatop: pte not valid");
			goto invalid;
		}
		a = pte & I386_PG_FRAME;
		ofs = _fvc_pt_find(kd, a, I386_PAGE_SIZE);
		if (ofs == -1) {
			_fvc_err(kd, kd->program,
	    "_i386_minidump_vatop: physical address 0x%jx not in minidump",
			    (uintmax_t)a);
			goto invalid;
		}
		*pa = ofs + offset;
		return (I386_PAGE_SIZE - offset);
	} else {
		_fvc_err(kd, kd->program,
	    "_i386_minidump_vatop: virtual address 0x%jx not minidumped",
		    (uintmax_t)va);
		goto invalid;
	}

invalid:
	_fvc_err(kd, 0, "invalid address (0x%jx)", (uintmax_t)va);
	return (0);
}

static int
_i386_minidump_kvatop(fvc_t *kd, fvc_addr_t va, off_t *pa)
{

	if (kd->vmst->hdr.paemode)
		return (_i386_minidump_vatop_pae(kd, va, pa));
	else
		return (_i386_minidump_vatop(kd, va, pa));
}

static vm_prot_t
_i386_entry_to_prot(uint64_t pte)
{
	vm_prot_t prot = FVC_VM_PROT_READ;

	/* Source: i386/pmap.c:pmap_protect() */
	if (pte & I386_PG_RW)
		prot |= FVC_VM_PROT_WRITE;
	if ((pte & I386_PG_NX) == 0)
		prot |= FVC_VM_PROT_EXECUTE;

	return prot;
}

struct i386_iter {
	fvc_t *kd;
	u_long nptes;
	u_long pteindex;
};

static void
_i386_iterator_init(struct i386_iter *it, fvc_t *kd)
{
	struct vmstate *vm = kd->vmst;

	it->kd = kd;
	it->pteindex = 0;
	if (vm->hdr.paemode) {
		it->nptes = vm->hdr.ptesize / sizeof(i386_pte_pae_t);
	} else {
		it->nptes = vm->hdr.ptesize / sizeof(i386_pte_t);
	}
	return;
}

static int
_i386_iterator_next(struct i386_iter *it, u_long *pa, u_long *va, u_long *dva,
    vm_prot_t *prot)
{
	struct vmstate *vm = it->kd->vmst;
	i386_pte_t pte32;
	i386_pte_pae_t pte64;
	int found = 0;

	*dva = 0;
	*pa = 0;
	*va = 0;
	*dva = 0;
	*prot = 0;
	for (; it->pteindex < it->nptes && found == 0; it->pteindex++) {
		if (vm->hdr.paemode) {
			pte64 = _i386_pte_pae_get(it->kd, it->pteindex);
			if ((pte64 & I386_PG_V) == 0)
				continue;
			*prot = _i386_entry_to_prot(pte64);
			*pa = pte64 & I386_PG_FRAME_PAE;
		} else {
			pte32 = _i386_pte_get(it->kd, it->pteindex);
			if ((pte32 & I386_PG_V) == 0)
				continue;
			*prot = _i386_entry_to_prot(pte32);
			*pa = pte32 & I386_PG_FRAME;
		}
		*va = vm->hdr.kernbase + (it->pteindex << I386_PAGE_SHIFT);
		found = 1;
	}
	return found;
}

static int
_i386_minidump_walk_pages(fvc_t *kd, fvc_walk_pages_cb_t *cb, void *arg)
{
	struct i386_iter it;
	u_long dva, pa, va;
	vm_prot_t prot;

	_i386_iterator_init(&it, kd);
	while (_i386_iterator_next(&it, &pa, &va, &dva, &prot)) {
		if (!_fvc_visit_cb(kd, cb, arg, pa, va, dva,
		    prot, I386_PAGE_SIZE, 0)) {
			return (0);
		}
	}
	return (1);
}

struct fvc_arch fvc_i386_minidump = {
	.ka_probe = _i386_minidump_probe,
	.ka_initvtop = _i386_minidump_initvtop,
	.ka_freevtop = _i386_minidump_freevtop,
	.ka_kvatop = _i386_minidump_kvatop,
	.ka_walk_pages = _i386_minidump_walk_pages,
};
