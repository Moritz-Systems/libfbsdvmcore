/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1999, Matthew Dillon.  All Rights Reserved.
 * Copyright (c) 2001, Thomas Moestl.  All Rights Reserved.
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/blist.h>
#include <sys/queue.h>

#include <vm/swap_pager.h>
#include <vm/vm_param.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <kvm.h>
#include <nlist.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "kvm_private.h"

static struct nlist kvm_swap_nl[] = {
	{ .n_name = "_swtailq" },	/* list of swap devices and sizes */
	{ .n_name = "_dmmax" },		/* maximum size of a swap block */
	{ .n_name = NULL }
};

#define NL_SWTAILQ	0
#define NL_DMMAX	1

static int kvm_swap_nl_cached = 0;
static int unswdev;  /* number of found swap dev's */
static int dmmax;

static int  kvm_getswapinfo_kvm(kvm_t *, struct kvm_swap *, int, int);
static int  nlist_init(kvm_t *);

#define KREAD(kd, addr, obj) \
	(kvm_read(kd, addr, (char *)(obj), sizeof(*obj)) != sizeof(*obj))
#define	KGET(idx, var)							\
	KGET2(kvm_swap_nl[(idx)].n_value, var, kvm_swap_nl[(idx)].n_name)
#define KGET2(addr, var, msg)						\
	if (KREAD(kd, (u_long)(addr), (var))) {				\
		_kvm_err(kd, kd->program, "cannot read %s", msg);	\
		return (-1);						\
	}

#define GETSWDEVNAME(dev, str, flags)					\
	if (dev == NODEV) {						\
		strlcpy(str, "[NFS swap]", sizeof(str));		\
	} else {							\
		snprintf(						\
		    str, sizeof(str),"%s%s",				\
		    ((flags & SWIF_DEV_PREFIX) ? _PATH_DEV : ""),	\
		    devname(dev, S_IFCHR)				\
		);							\
	}

int
kvm_getswapinfo(kvm_t *kd, struct kvm_swap *swap_ary, int swap_max, int flags)
{

	/*
	 * clear cache
	 */
	if (kd == NULL) {
		kvm_swap_nl_cached = 0;
		return(0);
	}

	return kvm_getswapinfo_kvm(kd, swap_ary, swap_max, flags);
}

int
kvm_getswapinfo_kvm(kvm_t *kd, struct kvm_swap *swap_ary, int swap_max,
    int flags)
{
	int i, ttl;
	TAILQ_HEAD(, swdevt) swtailq;
	struct swdevt *sp, swinfo;
	struct kvm_swap tot;

	if (!kd->arch->ka_native(kd)) {
		_kvm_err(kd, kd->program,
		    "cannot read swapinfo from non-native core");
		return (-1);
	}

	if (!nlist_init(kd))
		return (-1);

	bzero(&tot, sizeof(tot));
	KGET(NL_SWTAILQ, &swtailq);
	sp = TAILQ_FIRST(&swtailq);
	for (i = 0; sp != NULL; i++) {
		KGET2(sp, &swinfo, "swinfo");
		ttl = swinfo.sw_nblks - dmmax;
		if (i < swap_max - 1) {
			bzero(&swap_ary[i], sizeof(swap_ary[i]));
			swap_ary[i].ksw_total = ttl;
			swap_ary[i].ksw_used = swinfo.sw_used;
			swap_ary[i].ksw_flags = swinfo.sw_flags;
			GETSWDEVNAME(swinfo.sw_dev, swap_ary[i].ksw_devname,
			     flags);
		}
		tot.ksw_total += ttl;
		tot.ksw_used += swinfo.sw_used;
		sp = TAILQ_NEXT(&swinfo, sw_list);
	}

	if (i >= swap_max)
		i = swap_max - 1;
	if (i >= 0)
		swap_ary[i] = tot;

        return(i);
}

static int
nlist_init(kvm_t *kd)
{

	if (kvm_swap_nl_cached)
		return (1);

	if (kvm_nlist(kd, kvm_swap_nl) < 0)
		return (0);

	/* Required entries */
	if (kvm_swap_nl[NL_SWTAILQ].n_value == 0) {
		_kvm_err(kd, kd->program, "unable to find swtailq");
		return (0);
	}

	if (kvm_swap_nl[NL_DMMAX].n_value == 0) {
		_kvm_err(kd, kd->program, "unable to find dmmax");
		return (0);
	}

	/* Get globals, type of swap */
	KGET(NL_DMMAX, &dmmax);

	kvm_swap_nl_cached = 1;
	return (1);
}
