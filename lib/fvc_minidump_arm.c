/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2008 Semihalf, Grzegorz Bernacki
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
 *
 * From: FreeBSD: src/lib/libfvc/fvc_minidump_i386.c,v 1.2 2006/06/05 08:51:14
 */

/*
 * ARM machine dependent routines for fvc and minidumps.
 */

#include <sys/param.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "minidump/arm.h"

#include "fvc.h"
#include "fvc_private.h"
#include "fvc_arm.h"

#define	arm_round_page(x)	fvc_roundup2((fvc_addr_t)(x), ARM_PAGE_SIZE)

struct vmstate {
	struct		minidumphdr hdr;
	unsigned char	ei_data;
};

static arm_pt_entry_t
_arm_pte_get(fvc_t *kd, u_long pteindex)
{
	arm_pt_entry_t *pte = _fvc_pmap_get(kd, pteindex, sizeof(*pte));

	return _fvc32toh(kd, *pte);
}

static int
_arm_minidump_probe(fvc_t *kd)
{

	return (_fvc_probe_elf_kernel(kd, ELFCLASS32, EM_ARM) &&
	    _fvc_is_minidump(kd));
}

static void
_arm_minidump_freevtop(fvc_t *kd)
{
	struct vmstate *vm = kd->vmst;

	free(vm);
	kd->vmst = NULL;
}

static int
_arm_minidump_initvtop(fvc_t *kd)
{
	struct vmstate *vmst;
	off_t off, dump_avail_off, sparse_off;

	vmst = _fvc_malloc(kd, sizeof(*vmst));
	if (vmst == NULL) {
		_fvc_err(kd, kd->program, "cannot allocate vm");
		return (-1);
	}

	kd->vmst = vmst;

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
	vmst->hdr.kernbase = _fvc32toh(kd, vmst->hdr.kernbase);
	vmst->hdr.arch = _fvc32toh(kd, vmst->hdr.arch);
	vmst->hdr.mmuformat = _fvc32toh(kd, vmst->hdr.mmuformat);
	if (vmst->hdr.mmuformat == MINIDUMP_MMU_FORMAT_UNKNOWN) {
		/* This is a safe default as 1K pages are not used. */
		vmst->hdr.mmuformat = MINIDUMP_MMU_FORMAT_V6;
	}
	vmst->hdr.dumpavailsize = vmst->hdr.version == MINIDUMP_VERSION ?
	    _fvc32toh(kd, vmst->hdr.dumpavailsize) : 0;

	/* Skip header and msgbuf */
	dump_avail_off = ARM_PAGE_SIZE + arm_round_page(vmst->hdr.msgbufsize);

	/* Skip dump_avail */
	off = dump_avail_off + arm_round_page(vmst->hdr.dumpavailsize);

	sparse_off = off + arm_round_page(vmst->hdr.bitmapsize) +
	    arm_round_page(vmst->hdr.ptesize);
	if (_fvc_pt_init(kd, vmst->hdr.dumpavailsize, dump_avail_off,
	    vmst->hdr.bitmapsize, off, sparse_off, ARM_PAGE_SIZE) == -1) {
		return (-1);
	}
	off += arm_round_page(vmst->hdr.bitmapsize);

	if (_fvc_pmap_init(kd, vmst->hdr.ptesize, off) == -1) {
		return (-1);
	}
	off += arm_round_page(vmst->hdr.ptesize);

	return (0);
}

static int
_arm_minidump_kvatop(fvc_t *kd, fvc_addr_t va, off_t *pa)
{
	struct vmstate *vm;
	arm_pt_entry_t pte;
	arm_physaddr_t offset, a;
	fvc_addr_t pteindex;
	off_t ofs;

	vm = kd->vmst;

	if (va >= vm->hdr.kernbase) {
		pteindex = (va - vm->hdr.kernbase) >> ARM_PAGE_SHIFT;
		if (pteindex >= vm->hdr.ptesize / sizeof(pte))
			goto invalid;
		pte = _arm_pte_get(kd, pteindex);
		if ((pte & ARM_L2_TYPE_MASK) == ARM_L2_TYPE_INV) {
			_fvc_err(kd, kd->program,
			    "_arm_minidump_kvatop: pte not valid");
			goto invalid;
		}
		if ((pte & ARM_L2_TYPE_MASK) == ARM_L2_TYPE_L) {
			/* 64K page -> convert to be like 4K page */
			offset = va & ARM_L2_S_OFFSET;
			a = (pte & ARM_L2_L_FRAME) +
			    (va & ARM_L2_L_OFFSET & ARM_L2_S_FRAME);
		} else {
			if (kd->vmst->hdr.mmuformat == MINIDUMP_MMU_FORMAT_V4 &&
			    (pte & ARM_L2_TYPE_MASK) == ARM_L2_TYPE_T) {
				_fvc_err(kd, kd->program,
				    "_arm_minidump_kvatop: pte not supported");
				goto invalid;
			}
			/* 4K page */
			offset = va & ARM_L2_S_OFFSET;
			a = pte & ARM_L2_S_FRAME;
		}

		ofs = _fvc_pt_find(kd, a, ARM_PAGE_SIZE);
		if (ofs == -1) {
			_fvc_err(kd, kd->program, "_arm_minidump_kvatop: "
			    "physical address 0x%jx not in minidump",
			    (uintmax_t)a);
			goto invalid;
		}

		*pa = ofs + offset;
		return (ARM_PAGE_SIZE - offset);
	} else
		_fvc_err(kd, kd->program, "_arm_minidump_kvatop: virtual "
		    "address 0x%jx not minidumped", (uintmax_t)va);

invalid:
	_fvc_err(kd, 0, "invalid address (0x%jx)", (uintmax_t)va);
	return (0);
}

static fvc_vm_prot_t
_arm_entry_to_prot(fvc_t *kd, arm_pt_entry_t pte)
{
	struct vmstate *vm = kd->vmst;
	fvc_vm_prot_t prot = FVC_VM_PROT_READ;

	/* Source: arm/arm/pmap-v4.c:pmap_fault_fixup() */
	if (vm->hdr.mmuformat == MINIDUMP_MMU_FORMAT_V4) {
		if (pte & ARM_L2_S_PROT_W)
			prot |= FVC_VM_PROT_WRITE;
		return prot;
	}

	/* Source: arm/arm/pmap-v6.c:pmap_protect() */
	if ((pte & ARM_PTE2_RO) == 0)
		prot |= FVC_VM_PROT_WRITE;
	if ((pte & ARM_PTE2_NX) == 0)
		prot |= FVC_VM_PROT_EXECUTE;
	return prot;
}

static int
_arm_minidump_walk_pages(fvc_t *kd, fvc_walk_pages_cb_t *cb, void *arg)
{
	struct vmstate *vm = kd->vmst;
	u_long nptes = vm->hdr.ptesize / sizeof(arm_pt_entry_t);
	u_long dva, pa, pteindex, va;

	for (pteindex = 0; pteindex < nptes; pteindex++) {
		arm_pt_entry_t pte = _arm_pte_get(kd, pteindex);

		if ((pte & ARM_L2_TYPE_MASK) == ARM_L2_TYPE_INV)
			continue;

		va = vm->hdr.kernbase + (pteindex << ARM_PAGE_SHIFT);
		if ((pte & ARM_L2_TYPE_MASK) == ARM_L2_TYPE_L) {
			/* 64K page */
			pa = (pte & ARM_L2_L_FRAME) +
			    (va & ARM_L2_L_OFFSET & ARM_L2_S_FRAME);
		} else {
			if (vm->hdr.mmuformat == MINIDUMP_MMU_FORMAT_V4 &&
			    (pte & ARM_L2_TYPE_MASK) == ARM_L2_TYPE_T) {
				continue;
			}
			/* 4K page */
			pa = pte & ARM_L2_S_FRAME;
		}

		dva = 0; /* no direct map on this platform */
		if (!_fvc_visit_cb(kd, cb, arg, pa, va, dva,
		    _arm_entry_to_prot(kd, pte), ARM_PAGE_SIZE, 0))
			return (0);
	}
	return (1);
}

struct fvc_arch fvc_arm_minidump = {
	.ka_probe = _arm_minidump_probe,
	.ka_initvtop = _arm_minidump_initvtop,
	.ka_freevtop = _arm_minidump_freevtop,
	.ka_kvatop = _arm_minidump_kvatop,
	.ka_walk_pages = _arm_minidump_walk_pages,
};
