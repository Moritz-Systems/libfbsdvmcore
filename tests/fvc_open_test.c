/*-
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
 */

#include <sys/param.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include "fvc.h"
#include "fvc_test_common.h"

ATF_TC_WITHOUT_HEAD(fvc_open_negative_test_nonexistent_corefile);
ATF_TC_BODY(fvc_open_negative_test_nonexistent_corefile, tc)
{

	errbuf_clear();
	ATF_CHECK(fvc_open(NULL, "/nonexistent", NULL, NULL, NULL) == NULL);
	ATF_CHECK(!errbuf_has_error(errbuf));
	errbuf_clear();
	ATF_CHECK(fvc_open(NULL, "/nonexistent", errbuf, NULL, NULL) == NULL);
	ATF_CHECK(errbuf_has_error(errbuf));
}

ATF_TC_WITHOUT_HEAD(fvc_open_negative_test_nonexistent_execfile);
ATF_TC_BODY(fvc_open_negative_test_nonexistent_execfile, tc)
{

	errbuf_clear();
	ATF_CHECK(fvc_open("/nonexistent", _PATH_DEVZERO, NULL, NULL, NULL) ==
	    NULL);
	ATF_CHECK(strlen(errbuf) == 0);
	errbuf_clear();
	ATF_CHECK(fvc_open("/nonexistent", _PATH_DEVZERO, errbuf, NULL, NULL) ==
	    NULL);
	ATF_CHECK(errbuf_has_error(errbuf));
}

ATF_TC(fvc_open_negative_test_invalid_corefile);
ATF_TC_HEAD(fvc_open_negative_test_invalid_corefile, tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(fvc_open_negative_test_invalid_corefile, tc)
{
	fvc_t *kd;

	errbuf_clear();
	atf_utils_create_file("some-file", "this is a text file");
	kd = fvc_open(NULL, "some-file", errbuf, NULL, NULL);
	ATF_CHECK(errbuf_has_error(errbuf));
	ATF_REQUIRE_MSG(kd == NULL, "fvc_open succeeded");
}

ATF_TC(fvc_open_negative_test_invalid_execfile);
ATF_TC_HEAD(fvc_open_negative_test_invalid_execfile, tc)
{

	atf_tc_set_md_var(tc, "require.user", "root");
}

ATF_TC_BODY(fvc_open_negative_test_invalid_execfile, tc)
{
	fvc_t *kd;

	errbuf_clear();
	atf_utils_create_file("some-file", "this is a text file");
	kd = fvc_open("some-file", "/bin/sh", errbuf, NULL, NULL);
	ATF_CHECK(errbuf_has_error(errbuf));
	ATF_REQUIRE_MSG(kd == NULL, "fvc_open succeeded unexpectedly");
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fvc_open_negative_test_invalid_corefile);
	ATF_TP_ADD_TC(tp, fvc_open_negative_test_invalid_execfile);
	ATF_TP_ADD_TC(tp, fvc_open_negative_test_nonexistent_corefile);
	ATF_TP_ADD_TC(tp, fvc_open_negative_test_nonexistent_execfile);

	return (atf_no_error());
}
