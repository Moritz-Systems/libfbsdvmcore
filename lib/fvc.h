/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)fvc.h	8.1 (Berkeley) 6/2/93
 * $FreeBSD$
 */

#ifndef _FVC_H_
#define	_FVC_H_

#include <sys/types.h>
#include <stdint.h>

/* Default version symbol. */
#define	VRS_SYM		"_version"
#define	VRS_KEY		"VERSION"

typedef struct __fvc fvc_t;

struct proc;

typedef uint64_t fvc_addr_t;
typedef unsigned char fvc_vm_prot_t;

/* Constants from sys/vm/vm.h */
#define	FVC_VM_PROT_READ		((fvc_vm_prot_t) 0x01)
#define	FVC_VM_PROT_WRITE		((fvc_vm_prot_t) 0x02)
#define	FVC_VM_PROT_EXECUTE		((fvc_vm_prot_t) 0x04)

struct fvc_page {
	unsigned int	kp_version;
	fvc_addr_t	kp_paddr;
	fvc_addr_t	kp_kmap_vaddr;
	fvc_addr_t	kp_dmap_vaddr;
	fvc_vm_prot_t	kp_prot;
	off_t		kp_offset;
	size_t		kp_len;
	/* end of version 2 */
};

#define SWIF_DEV_PREFIX	0x0002
#define	LIBFVC_WALK_PAGES_VERSION	2

__BEGIN_DECLS
int	  fvc_close(fvc_t *);
char	 *fvc_geterr(fvc_t *);
int	  fvc_native(fvc_t *);
fvc_t	 *fvc_open
	    (const char *, const char *, char *,
	    int (*)(const char *, fvc_addr_t *, void *), void *);
ssize_t	  fvc_read(fvc_t *, fvc_addr_t, void *, size_t);
ssize_t   fvc_kerndisp(fvc_t *);

typedef int fvc_walk_pages_cb_t(struct fvc_page *, void *);
int fvc_walk_pages(fvc_t *, fvc_walk_pages_cb_t *, void *);
__END_DECLS

#endif /* !_FVC_H_ */
