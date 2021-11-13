/*-
 * Copyright (c) 2020 Alfredo Dal'Ava Junior <alfredo@freebsd.org>
 * Copyright (c) 2017 Enji Cooper <ngie@freebsd.org>
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
 * From: FreeBSD: src/lib/libkvm/tests/kvm_geterr_test.c
 */

#include <sys/param.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <atf-c.h>

#include "fvc.h"
#include "fvc_private.h"
#include "fvc_test_common.h"

ATF_TC(fvc_read_positive_test_no_error);
ATF_TC_HEAD(fvc_read_positive_test_no_error, tc)
{

	atf_tc_set_md_var(tc, "descr",
	    "test that fvc_read returns a sane value");
	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(fvc_read_positive_test_no_error, tc)
{
	fvc_t *kd;
	struct fvc_nlist nl[] = {
#define	SYMNAME	"_mp_maxcpus"
#define	X_MAXCPUS	0
		{ SYMNAME, 0, 0 },
		{ NULL, 0, 0 },
	};
	ssize_t rc;
	int sysctl_maxcpus, mp_maxcpus, retcode;
	size_t len = sizeof(sysctl_maxcpus);

	errbuf_clear();
	kd = fvc_open(NULL, NULL, O_RDONLY, errbuf, NULL, NULL);
	ATF_CHECK(!errbuf_has_error(errbuf));
	ATF_REQUIRE_MSG(kd != NULL, "fvc_open failed: %s", errbuf);
	retcode = _fvc_nlist(kd, nl);
	ATF_REQUIRE_MSG(retcode != -1,
	    "_fvc_nlist failed (returned %d): %s", retcode, fvc_geterr(kd));
	if (nl[X_MAXCPUS].n_type == 0)
		atf_tc_skip("symbol (\"%s\") couldn't be found", SYMNAME);

	rc = fvc_read(kd, nl[X_MAXCPUS].n_value, &mp_maxcpus,
	    sizeof(mp_maxcpus));

	ATF_REQUIRE_MSG(rc != -1, "fvc_read failed: %s", fvc_geterr(kd));
	ATF_REQUIRE_MSG(fvc_close(kd) == 0, "fvc_close failed: %s",
	    strerror(errno));

	/* Check if value read from fvc_read is sane */
        retcode = sysctlbyname("kern.smp.maxcpus", &sysctl_maxcpus, &len, NULL, 0);
	ATF_REQUIRE_MSG(retcode == 0, "sysctl read failed : %d", retcode);
	ATF_REQUIRE_EQ_MSG(mp_maxcpus, sysctl_maxcpus,
	    "failed: fvc_read of mp_maxcpus returned %d but sysctl maxcpus returned %d",
	    mp_maxcpus, sysctl_maxcpus);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fvc_read_positive_test_no_error);
	return (atf_no_error());
}
