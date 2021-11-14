/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
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

#include <sys/user.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <stdbool.h>

#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fvc.h"
#include "fvc_private.h"

extern struct fvc_arch fvc_aarch64_minidump;
extern struct fvc_arch fvc_amd64;
extern struct fvc_arch fvc_amd64_minidump;
extern struct fvc_arch fvc_arm;
extern struct fvc_arch fvc_arm_minidump;
extern struct fvc_arch fvc_i386;
extern struct fvc_arch fvc_i386_minidump;
extern struct fvc_arch fvc_mips_minidump;
extern struct fvc_arch fvc_powerpc64;
extern struct fvc_arch fvc_powerpc64_minidump;
extern struct fvc_arch fvc_powerpc64le;
extern struct fvc_arch fvc_powerpc;
extern struct fvc_arch fvc_riscv_minidump;

struct fvc_arch *fvc_arches[] = {
	&fvc_aarch64_minidump,
	&fvc_amd64,
	&fvc_amd64_minidump,
	&fvc_arm,
	&fvc_arm_minidump,
	&fvc_i386,
	&fvc_i386_minidump,
	&fvc_mips_minidump,
	&fvc_powerpc64,
	&fvc_powerpc64_minidump,
	&fvc_powerpc64le,
	&fvc_powerpc,
	&fvc_riscv_minidump,
	NULL
};

static char _kd_is_null[] = "";

char *
fvc_geterr(fvc_t *kd)
{

	if (kd == NULL)
		return (_kd_is_null);
	return (kd->errbuf);
}

static int
_fvc_read_kernel_ehdr(fvc_t *kd)
{
	Elf *elf;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		_fvc_err(kd, kd->program, "Unsupported libelf");
		return (-1);
	}
	elf = elf_begin(kd->nlfd, ELF_C_READ, NULL);
	if (elf == NULL) {
		_fvc_err(kd, kd->program, "%s", elf_errmsg(0));
		return (-1);
	}
	if (elf_kind(elf) != ELF_K_ELF) {
		_fvc_err(kd, kd->program, "kernel is not an ELF file");
		return (-1);
	}
	if (gelf_getehdr(elf, &kd->nlehdr) == NULL) {
		_fvc_err(kd, kd->program, "%s", elf_errmsg(0));
		elf_end(elf);
		return (-1);
	}
	elf_end(elf);

	switch (kd->nlehdr.e_ident[EI_DATA]) {
	case ELFDATA2LSB:
	case ELFDATA2MSB:
		return (0);
	default:
		_fvc_err(kd, kd->program,
		    "unsupported ELF data encoding for kernel");
		return (-1);
	}
}

static fvc_t *
_fvc_open(fvc_t *kd, const char *uf, const char *mf, int flag, char *errout)
{
	struct fvc_arch **parch;
	struct stat st;

	kd->pmfd = -1;
	kd->nlfd = -1;
	kd->vmst = NULL;

	if (uf == NULL)
		uf = getbootfile();
	else if (strlen(uf) >= MAXPATHLEN) {
		_fvc_err(kd, kd->program, "exec file name too long");
		goto failed;
	}
	if (flag & ~O_RDWR) {
		_fvc_err(kd, kd->program, "bad flags arg");
		goto failed;
	}
	if (mf == NULL)
		mf = _PATH_MEM;

	if ((kd->pmfd = open(mf, flag | O_CLOEXEC, 0)) < 0) {
		_fvc_syserr(kd, kd->program, "%s", mf);
		goto failed;
	}
	if (fstat(kd->pmfd, &st) < 0) {
		_fvc_syserr(kd, kd->program, "%s", mf);
		goto failed;
	}
	if (S_ISREG(st.st_mode) && st.st_size <= 0) {
		errno = EINVAL;
		_fvc_syserr(kd, kd->program, "empty file");
		goto failed;
	}
	if (!S_ISREG(st.st_mode)) {
		errno = EINVAL;
		_fvc_syserr(kd, kd->program, "not a regular file");
		goto failed;
	}

	/*
	 * This is either a crash dump or a remote live system with its physical
	 * memory fully accessible via a special device.
	 * Open the namelist fd and determine the architecture.
	 */
	if ((kd->nlfd = open(uf, O_RDONLY | O_CLOEXEC, 0)) < 0) {
		_fvc_syserr(kd, kd->program, "%s", uf);
		goto failed;
	}
	if (_fvc_read_kernel_ehdr(kd) < 0)
		goto failed;
	if (strncmp(mf, _PATH_FWMEM, strlen(_PATH_FWMEM)) == 0 ||
	    strncmp(mf, _PATH_DEVVMM, strlen(_PATH_DEVVMM)) == 0) {
		kd->rawdump = 1;
		kd->writable = 1;
	}
	for (parch = fvc_arches; *parch; parch++) {
		if ((*parch)->ka_probe(kd)) {
			kd->arch = *parch;
			break;
		}
	}
	if (kd->arch == NULL) {
		_fvc_err(kd, kd->program, "unsupported architecture");
		goto failed;
	}

	/*
	 * Initialize the virtual address translation machinery.
	 */
	if (kd->arch->ka_initvtop(kd) < 0)
		goto failed;
	return (kd);
failed:
	/*
	 * Copy out the error if doing sane error semantics.
	 */
	if (errout != NULL)
		strlcpy(errout, kd->errbuf, _POSIX2_LINE_MAX);
	(void)fvc_close(kd);
	return (NULL);
}

fvc_t *
fvc_open(const char *uf, const char *mf, int flag, char *errout,
    int (*resolver)(const char *, fvc_addr_t *, void *),
    void *resolver_data)
{
	fvc_t *kd;

	if ((kd = calloc(1, sizeof(*kd))) == NULL) {
		if (errout != NULL)
			(void)strlcpy(errout, strerror(errno),
			    _POSIX2_LINE_MAX);
		return (NULL);
	}

	if (resolver != NULL) {
		kd->resolve_symbol = resolver;
		kd->resolve_symbol_data = resolver_data;
	} else {
		kd->resolve_symbol = _fvc_libelf_resolver;
		if (_fvc_libelf_resolver_data_init(kd, uf) != 0)
			return (NULL);
	}
	return (_fvc_open(kd, uf, mf, flag, errout));
}

int
fvc_close(fvc_t *kd)
{
	int error = 0;

	if (kd == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (kd->vmst != NULL)
		kd->arch->ka_freevtop(kd);
	if (kd->pmfd >= 0)
		error |= close(kd->pmfd);
	if (kd->nlfd >= 0)
		error |= close(kd->nlfd);
	if (kd->pt_map != NULL)
		free(kd->pt_map);
	if (kd->page_map != NULL)
		free(kd->page_map);
	if (kd->sparse_map != MAP_FAILED)
		munmap(kd->sparse_map, kd->pt_sparse_size);
	free((void *)kd);

	return (error);
}

ssize_t
fvc_read(fvc_t *kd, fvc_addr_t kva, void *buf, size_t len)
{
	int cc;
	ssize_t cr;
	off_t pa;
	char *cp;

	cp = buf;
	while (len > 0) {
		cc = kd->arch->ka_kvatop(kd, kva, &pa);
		if (cc == 0)
			return (-1);
		if (cc > (ssize_t)len)
			cc = len;
		errno = 0;
		if (lseek(kd->pmfd, pa, 0) == -1 && errno != 0) {
			_fvc_syserr(kd, 0, _PATH_MEM);
			break;
		}
		cr = read(kd->pmfd, cp, cc);
		if (cr < 0) {
			_fvc_syserr(kd, kd->program, "fvc_read");
			break;
		}
		/*
		 * If ka_kvatop returns a bogus value or our core file is
		 * truncated, we might wind up seeking beyond the end of the
		 * core file in which case the read will return 0 (EOF).
		 */
		if (cr == 0)
			break;
		cp += cr;
		kva += cr;
		len -= cr;
	}

	return (cp - (char *)buf);
}

ssize_t
fvc_write(fvc_t *kd, u_long kva, const void *buf, size_t len)
{
	int cc;
	ssize_t cw;
	off_t pa;
	const char *cp;

	if (!kd->writable) {
		_fvc_err(kd, kd->program,
		    "fvc_write not implemented for dead kernels");
		return (-1);
	}

	cp = buf;
	while (len > 0) {
		cc = kd->arch->ka_kvatop(kd, kva, &pa);
		if (cc == 0)
			return (-1);
		if (cc > (ssize_t)len)
			cc = len;
		errno = 0;
		if (lseek(kd->pmfd, pa, 0) == -1 && errno != 0) {
			_fvc_syserr(kd, 0, _PATH_MEM);
			break;
		}
		cw = write(kd->pmfd, cp, cc);
		if (cw < 0) {
			_fvc_syserr(kd, kd->program, "fvc_write");
			break;
		}
		/*
		 * If ka_kvatop returns a bogus value or our core file is
		 * truncated, we might wind up seeking beyond the end of the
		 * core file in which case the read will return 0 (EOF).
		 */
		if (cw == 0)
			break;
		cp += cw;
		kva += cw;
		len -= cw;
	}

	return (cp - (const char *)buf);
}

int
fvc_walk_pages(fvc_t *kd, fvc_walk_pages_cb_t *cb, void *closure)
{

	if (kd->arch->ka_walk_pages == NULL)
		return (0);

	return (kd->arch->ka_walk_pages(kd, cb, closure));
}

ssize_t
fvc_kerndisp(fvc_t *kd)
{
	unsigned long kernbase, rel_kernbase;
	size_t kernbase_len = sizeof(kernbase);
	size_t rel_kernbase_len = sizeof(rel_kernbase);

	if (kd->arch->ka_kerndisp == NULL)
		return (0);

	return (kd->arch->ka_kerndisp(kd));
}
