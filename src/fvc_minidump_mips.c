/*- SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2010 Oleksandr Tymoshenko Copyright (c) 2008 Semihalf,
 * Grzegorz Bernacki Copyright (c) 2006 Peter Wemm
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.  2. Redistributions in
 * binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * From: FreeBSD: src/lib/libfvc/fvc_minidump_arm.c r214223
 */

/*
 * MIPS machine dependent routines for fvc and minidumps.
 */

#include <sys/param.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../sys/mips/include/cca.h"
#define	_KVM_MINIDUMP
#include "../../sys/mips/include/cpuregs.h"
#include "../../sys/mips/include/minidump.h"

#include "fvc.h"
#include "fvc_private.h"
#include "fvc_mips.h"

#define	mips_round_page(x)	roundup2((fvc_addr_t)(x), MIPS_PAGE_SIZE)

struct vmstate {
	struct		minidumphdr hdr;
	int		pte_size;
};

static int
_mips_minidump_probe(fvc_t *kd)
{

	if (kd->nlehdr.e_ident[EI_CLASS] != ELFCLASS32 &&
	    kd->nlehdr.e_ident[EI_CLASS] != ELFCLASS64)
		return (0);
	if (kd->nlehdr.e_machine != EM_MIPS)
		return (0);
	return (_fvc_is_minidump(kd));
}

static void
_mips_minidump_freevtop(fvc_t *kd)
{
	struct vmstate *vm = kd->vmst;

	free(vm);
	kd->vmst = NULL;
}

static int
_mips_minidump_initvtop(fvc_t *kd)
{
	struct vmstate *vmst;
	off_t off, dump_avail_off, sparse_off;

	vmst = _fvc_malloc(kd, sizeof(*vmst));
	if (vmst == NULL) {
		_fvc_err(kd, kd->program, "cannot allocate vm");
		return (-1);
	}

	kd->vmst = vmst;

	if (kd->nlehdr.e_ident[EI_CLASS] == ELFCLASS64 ||
	    kd->nlehdr.e_flags & EF_MIPS_ABI2)
		vmst->pte_size = 64;
	else
		vmst->pte_size = 32;

	if (pread(kd->pmfd, &vmst->hdr,
	    sizeof(vmst->hdr), 0) != sizeof(vmst->hdr)) {
		_fvc_err(kd, kd->program, "cannot read dump header");
		return (-1);
	}

	if (strncmp(MINIDUMP_MAGIC, vmst->hdr.magic,
	    sizeof(vmst->hdr.magic)) != 0) {
		_fvc_err(kd, kd->program, "not a minidump for this platform");
		return (-1);
	}
	vmst->hdr.version = _fvc32toh(kd, vmst->hdr.version);
	if (vmst->hdr.version != MINIDUMP_VERSION && vmst->hdr.version != 1) {
		_fvc_err(kd, kd->program, "wrong minidump version. "
		    "Expected %d got %d", MINIDUMP_VERSION, vmst->hdr.version);
		return (-1);
	}
	vmst->hdr.msgbufsize = _fvc32toh(kd, vmst->hdr.msgbufsize);
	vmst->hdr.bitmapsize = _fvc32toh(kd, vmst->hdr.bitmapsize);
	vmst->hdr.ptesize = _fvc32toh(kd, vmst->hdr.ptesize);
	vmst->hdr.kernbase = _fvc64toh(kd, vmst->hdr.kernbase);
	vmst->hdr.dmapbase = _fvc64toh(kd, vmst->hdr.dmapbase);
	vmst->hdr.dmapend = _fvc64toh(kd, vmst->hdr.dmapend);
	vmst->hdr.dumpavailsize = vmst->hdr.version == MINIDUMP_VERSION ?
	    _fvc32toh(kd, vmst->hdr.dumpavailsize) : 0;

	/* Skip header and msgbuf */
	dump_avail_off = MIPS_PAGE_SIZE + mips_round_page(vmst->hdr.msgbufsize);

	/* Skip dump_avail */
	off = dump_avail_off + mips_round_page(vmst->hdr.dumpavailsize);

	sparse_off = off + mips_round_page(vmst->hdr.bitmapsize) +
	    mips_round_page(vmst->hdr.ptesize);
	if (_fvc_pt_init(kd, vmst->hdr.dumpavailsize, dump_avail_off,
	    vmst->hdr.bitmapsize, off, sparse_off, MIPS_PAGE_SIZE) == -1) {
		return (-1);
	}
	off += mips_round_page(vmst->hdr.bitmapsize);

	if (_fvc_pmap_init(kd, vmst->hdr.ptesize, off) == -1) {
		return (-1);
	}
	off += mips_round_page(vmst->hdr.ptesize);

	return (0);
}

static int
_mips_minidump_kvatop(fvc_t *kd, fvc_addr_t va, off_t *pa)
{
	struct vmstate *vm;
	mips_physaddr_t offset, a;
	fvc_addr_t pteindex;
	u_long valid;
	off_t ofs;
	mips32_pte_t pte32;
	mips64_pte_t pte64;

	offset = va & MIPS_PAGE_MASK;
	/* Operate with page-aligned address */
	va &= ~MIPS_PAGE_MASK;

	vm = kd->vmst;
	if (kd->nlehdr.e_ident[EI_CLASS] == ELFCLASS64) {
		if (va >= MIPS_XKPHYS_START && va < MIPS_XKPHYS_END) {
			a = va & MIPS_XKPHYS_PHYS_MASK;
			goto found;
		}
		if (va >= MIPS64_KSEG0_START && va < MIPS64_KSEG0_END) {
			a = va & MIPS_KSEG0_PHYS_MASK;
			goto found;
		}
		if (va >= MIPS64_KSEG1_START && va < MIPS64_KSEG1_END) {
			a = va & MIPS_KSEG0_PHYS_MASK;
			goto found;
		}
	} else {
		if (va >= MIPS32_KSEG0_START && va < MIPS32_KSEG0_END) {
			a = va & MIPS_KSEG0_PHYS_MASK;
			goto found;
		}
		if (va >= MIPS32_KSEG1_START && va < MIPS32_KSEG1_END) {
			a = va & MIPS_KSEG0_PHYS_MASK;
			goto found;
		}
	}
	if (va >= vm->hdr.kernbase) {
		pteindex = (va - vm->hdr.kernbase) >> MIPS_PAGE_SHIFT;
		if (vm->pte_size == 64) {
			valid = pteindex < vm->hdr.ptesize / sizeof(pte64);
			if (pteindex >= vm->hdr.ptesize / sizeof(pte64))
				goto invalid;
			pte64 = _mips64_pte_get(kd, pteindex);
			valid = pte64 & MIPS_PTE_V;
			if (valid)
				a = MIPS64_PTE_TO_PA(pte64);
		} else {
			if (pteindex >= vm->hdr.ptesize / sizeof(pte32))
				goto invalid;
			pte32 = _mips32_pte_get(kd, pteindex);
			valid = pte32 & MIPS_PTE_V;
			if (valid)
				a = MIPS32_PTE_TO_PA(pte32);
		}
		if (!valid) {
			_fvc_err(kd, kd->program, "_mips_minidump_kvatop: pte "
			    "not valid");
			goto invalid;
		}
	} else {
		_fvc_err(kd, kd->program, "_mips_minidump_kvatop: virtual "
		    "address 0x%jx not minidumped", (uintmax_t)va);
		return (0);
	}

found:
	ofs = _fvc_pt_find(kd, a, MIPS_PAGE_SIZE);
	if (ofs == -1) {
		_fvc_err(kd, kd->program, "_mips_minidump_kvatop: physical "
		    "address 0x%jx not in minidump", (uintmax_t)a);
		goto invalid;
	}

	*pa = ofs + offset;
	return (MIPS_PAGE_SIZE - offset);


invalid:
	_fvc_err(kd, 0, "invalid address (0x%jx)", (uintmax_t)va);
	return (0);
}

struct mips_iter {
	fvc_t *kd;
	u_long nptes;
	u_long pteindex;
};

static void
_mips_iterator_init(struct mips_iter *it, fvc_t *kd)
{
	struct vmstate *vm = kd->vmst;

	it->kd = kd;
	it->pteindex = 0;
	if (vm->pte_size == 64)
		it->nptes = vm->hdr.ptesize / sizeof(mips64_pte_t);
	else
		it->nptes = vm->hdr.ptesize / sizeof(mips32_pte_t);
	return;
}

static int
_mips_iterator_next(struct mips_iter *it, u_long *pa, u_long *va, u_long *dva,
    vm_prot_t *prot)
{
	struct vmstate *vm = it->kd->vmst;
	int found = 0;
	mips64_pte_t pte64;
	mips32_pte_t pte32;

	/*
	 * mips/mips/pmap.c: init_pte_prot / pmap_protect indicate that all
	 * pages are R|X at least.
	 */
	*prot = FVC_VM_PROT_READ | FVC_VM_PROT_EXECUTE;
	*pa = 0;
	*va = 0;
	*dva = 0;
	for (;it->pteindex < it->nptes && found == 0; it->pteindex++) {
		if (vm->pte_size == 64) {
			pte64 = _mips64_pte_get(it->kd, it->pteindex);
			if ((pte64 & MIPS_PTE_V) == 0)
				continue;
			if ((pte64 & MIPS64_PTE_RO) == 0)
				*prot |= FVC_VM_PROT_WRITE;
			*pa = MIPS64_PTE_TO_PA(pte64);
		} else {
			pte32 = _mips32_pte_get(it->kd, it->pteindex);
			if ((pte32 & MIPS_PTE_V) == 0)
				continue;
			if ((pte32 & MIPS32_PTE_RO) == 0)
				*prot |= FVC_VM_PROT_WRITE;
			*pa = MIPS32_PTE_TO_PA(pte32);
		}
		*va = vm->hdr.kernbase + (it->pteindex << MIPS_PAGE_SHIFT);
		found = 1;
		/* advance pteindex regardless */
	}

	return found;
}

static int
_mips_minidump_walk_pages(fvc_t *kd, fvc_walk_pages_cb_t *cb, void *arg)
{
	struct mips_iter it;
	u_long dva, pa, va;
	vm_prot_t prot;

	/* Generate direct mapped entries; need page entries for prot etc? */
	if (kd->nlehdr.e_ident[EI_CLASS] == ELFCLASS64) {
		/* MIPS_XKPHYS_START..MIPS_XKPHYS_END */
		/* MIPS64_KSEG0_START..MIPS64_KSEG0_END */
		/* MIPS64_KSEG1_START..MIPS64_KSEG1_START */
	} else {
		/* MIPS32_KSEG0_START..MIPS32_KSEG0_END */
		/* MIPS32_KSEG1_START..MIPS32_KSEG1_END */
	}

	_mips_iterator_init(&it, kd);
	while (_mips_iterator_next(&it, &pa, &va, &dva, &prot)) {
		if (!_fvc_visit_cb(kd, cb, arg, pa, va, dva,
		    prot, MIPS_PAGE_SIZE, 0)) {
			return (0);
		}
	}
	return (1);
}

struct fvc_arch fvc_mips_minidump = {
	.ka_probe = _mips_minidump_probe,
	.ka_initvtop = _mips_minidump_initvtop,
	.ka_freevtop = _mips_minidump_freevtop,
	.ka_kvatop = _mips_minidump_kvatop,
	.ka_walk_pages = _mips_minidump_walk_pages,
};
