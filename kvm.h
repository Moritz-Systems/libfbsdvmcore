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
 *	@(#)kvm.h	8.1 (Berkeley) 6/2/93
 * $FreeBSD$
 */

#ifndef _KVM_H_
#define	_KVM_H_

#include <sys/types.h>

/*
 * Including vm/vm.h causes namespace pollution issues.  For the
 * most part, only things using kvm_walk_pages() need to #include it.
 */
#ifndef VM_H
typedef u_char vm_prot_t;
#endif

/* Default version symbol. */
#define	VRS_SYM		"_version"
#define	VRS_KEY		"VERSION"

typedef struct __kvm kvm_t;

struct kinfo_proc;
struct proc;

struct kvm_swap {
	char		ksw_devname[32];
	unsigned int	ksw_used;
	unsigned int	ksw_total;
	int		ksw_flags;
	unsigned int	ksw_reserved1;
	unsigned int	ksw_reserved2;
};

struct kvm_page {
	unsigned int	kp_version;
	kpaddr_t	kp_paddr;
	kvaddr_t	kp_kmap_vaddr;
	kvaddr_t	kp_dmap_vaddr;
	vm_prot_t	kp_prot;
	off_t		kp_offset;
	size_t		kp_len;
	/* end of version 2 */
};

#define SWIF_DEV_PREFIX	0x0002
#define	LIBKVM_WALK_PAGES_VERSION	2

__BEGIN_DECLS
int	  kvm_close(kvm_t *);
char	 *kvm_geterr(kvm_t *);
int	  kvm_native(kvm_t *);
kvm_t	 *kvm_open2
	    (const char *, const char *, int, char *,
	    int (*)(const char *, kvaddr_t *));
ssize_t	  kvm_read2(kvm_t *, kvaddr_t, void *, size_t);
ssize_t	  kvm_write(kvm_t *, unsigned long, const void *, size_t);
kssize_t  kvm_kerndisp(kvm_t *);

typedef int kvm_walk_pages_cb_t(struct kvm_page *, void *);
int kvm_walk_pages(kvm_t *, kvm_walk_pages_cb_t *, void *);
__END_DECLS

#endif /* !_KVM_H_ */
