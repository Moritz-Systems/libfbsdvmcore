/*
 * based on the work of Bora Ozarslan
 * submitted to https://reviews.freebsd.org/D19253
 */

#include "fvc.h"
#include "fvc_private.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <libelf.h>
#include <gelf.h>
#include <unistd.h>
#include <err.h>

/* A range is a contiguous sets of pages in the minidump. */
struct range_info {
	u_long vaddr;	/* Vaddr of the range. */
	u_long off;	/* Offset of range in the original core file. */
	u_char prot;	/* Protection flags of range. */
	void* buf;	/* The data inside the range to write out. */
	size_t rangelen;/* The length of the range. */
	size_t filelen;	/* The length of the buf. */
};

static struct range_info* ranges;
static int ranges_len, ranges_cap;

static char fvc_err[_POSIX2_LINE_MAX];

void merge_ranges(void) {
	int rin_memory, lin_memory, i, j;

	for (i = 0; i < ranges_len; ++i) {
		rin_memory = (ranges[i].off != -1);
		for (j = 0; j < ranges_len; ++j) {
			lin_memory = (ranges[j].off != -1);
			if (i != j &&
			ranges[j].vaddr + ranges[j].rangelen == ranges[i].vaddr &&
			(lin_memory || !rin_memory) &&
			ranges[j].prot == ranges[i].prot) {
				ranges[j].rangelen += ranges[i].rangelen;
				ranges[j].filelen += ranges[i].filelen;
				if (!rin_memory && lin_memory)
					ranges[j].off = -1;
				ranges[i] = ranges[ranges_len-1];
				ranges_len -= 1;
				i -= 1;
				break;
			}
		}
	}
}

static int walk_pages_cb(struct fvc_page* page, void* arg) {
	int not_in_memory, i;
	u_char prot;

	/* NOTE: We don't care about pages that don't have a kernel vaddr. */
	if (page->kp_kmap_vaddr == 0)
		return 1;

	prot = 0;
	if (page->kp_prot & FVC_VM_PROT_READ) prot |= PF_R;
	if (page->kp_prot & FVC_VM_PROT_WRITE) prot |= PF_W;
	if (page->kp_prot & FVC_VM_PROT_EXECUTE) prot |= PF_X;

	not_in_memory = (page->kp_offset == -1);

	for (i = ranges_len - 1; i >= 0; --i) {
		if (ranges[i].vaddr == page->kp_kmap_vaddr)
			errx(EXIT_FAILURE, "Duplicate kernel vaddr found.");

		if (ranges[i].vaddr + ranges[i].rangelen == page->kp_kmap_vaddr &&
			prot == ranges[i].prot) {

			if (not_in_memory && ranges[i].off + 1 != 0)
				continue;

			if (not_in_memory)
				ranges[i].off = page->kp_offset;

			ranges[i].rangelen += page->kp_len;
			if (ranges[i].off != -1)
				ranges[i].filelen += page->kp_len;

			return 1;
		}
	}

	if (ranges_len == ranges_cap) {
		ranges_cap *= 2;
		ranges = realloc(ranges, ranges_cap * sizeof(struct range_info));
	}

	ranges[ranges_len].vaddr = page->kp_kmap_vaddr;
	ranges[ranges_len].rangelen = page->kp_len;
	if (not_in_memory)
		ranges[ranges_len].filelen = 0;
	else
		ranges[ranges_len].filelen = page->kp_len;
	ranges[ranges_len].off = page->kp_offset;
	ranges[ranges_len].prot = prot;

	ranges_len += 1;
	return 1;
}

static void usage(void) {
	errx(EXIT_FAILURE, "usage: minidump-to-elf minidump kernel [elf-output]");
}

int main(int argc, char** argv) {
	fvc_t* fvc;
	Elf* e;
	GElf_Ehdr *core_header, *ehdr;
	GElf_Phdr* phdr;
	GElf_Shdr shdr;
	Elf_Scn* section;
	Elf_Data* data;
	const char *kernel, *vmcore, *output_elf;
	size_t cr;
	int pagesize, elf_class, fd, i;

	if (argc != 3 && argc != 4)
		usage();

	output_elf = "vmcore.elf";
	vmcore = argv[1];
	kernel = argv[2];
	if (argc == 4)
		output_elf = argv[3];

	if ((fvc = fvc_open(kernel, vmcore, fvc_err, NULL, NULL)) == NULL)
		errx(EXIT_FAILURE, "Failed to open vmcore: %s\n", fvc_err);

	ranges_len = 0;
	ranges_cap = 128;
	ranges = calloc(ranges_cap, sizeof(struct range_info));

	if (fvc_walk_pages(fvc, walk_pages_cb, NULL) == 0)
		errx(EXIT_FAILURE, "fvc_walk_pages() failed");

	merge_ranges();
	
	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(EXIT_FAILURE, "Elf library initialization failed: %s",
			elf_errmsg(-1));

	if ((fd = open(output_elf, O_WRONLY | O_CREAT, 0777)) < 0)
		errx(EXIT_FAILURE, "Couldn't open 'core-elf' for writing");

	if ((e = elf_begin(fd, ELF_C_WRITE, NULL)) == NULL)
		errx(EXIT_FAILURE, "elf_begin() failed: %s",
			elf_errmsg(-1));

	core_header = &fvc->nlehdr;
	elf_class = core_header->e_ident[EI_CLASS];

	if ((ehdr = gelf_newehdr(e, elf_class)) == NULL)
		errx(EXIT_FAILURE, "gelf_newehdr() failed: %s",
			elf_errmsg(-1));

	ehdr->e_ident[EI_DATA] = core_header->e_ident[EI_DATA];
	ehdr->e_ident[EI_CLASS] = elf_class;
	ehdr->e_machine = core_header->e_machine;
	ehdr->e_type = ET_CORE;
	ehdr->e_ident[EI_OSABI] = core_header->e_ident[EI_OSABI];

	/* Page size is only different for sparc64 according to man arch. */ 
	pagesize = 4096;
	if (ehdr->e_machine == EM_SPARCV9)
		pagesize = 8192;

	if ((phdr = gelf_newphdr(e, ranges_len + 1)) < 0)
		errx(EXIT_FAILURE, "gelf_newphdr() failed: %s",
			elf_errmsg(-1));

	/* Put the ranges inside the data segment of sections. */
	for (i = 0; i < ranges_len; ++i) {
		ranges[i].buf = malloc(ranges[i].filelen);
		cr = fvc_read(fvc, ranges[i].vaddr, ranges[i].buf,
				ranges[i].filelen);

		if (cr != ranges[i].filelen) {
			ranges[i].filelen = 0;
			fprintf(stderr, "fvc_read() failed: %s\n", fvc_geterr(fvc));
		}

		if ((section = elf_newscn(e)) == NULL)
			errx(EXIT_FAILURE, "elf_newscn() failed: %s",
				elf_errmsg(-1));

		if ((data = elf_newdata(section)) == NULL)
			errx(EXIT_FAILURE, "elf_newdata() failed: %s",
				elf_errmsg(-1));

		/* Fill in the data part of the section */
		data->d_align = pagesize;
		data->d_off = 0LL;
		data->d_buf= ranges[i].buf;
		data->d_type = ELF_T_WORD; 
		data->d_size = ranges[i].filelen;
		data->d_version = EV_CURRENT;

		/* Update the section headers to have data in it. */
		if (&shdr != gelf_getshdr(section, &shdr))
			errx(EXIT_FAILURE, "gelf_getshdr() failed: %s", 
				elf_errmsg(-1));

		shdr.sh_name = i;
		shdr.sh_type = SHT_PROGBITS;
		shdr.sh_flags = SHF_OS_NONCONFORMING;
		shdr.sh_entsize = 0;
		shdr.sh_addr = ranges[i].vaddr;
		if (gelf_update_shdr(section, &shdr) == 0)
			errx(EXIT_FAILURE, "gelf_update_shdr() failed: %s",
				elf_errmsg(-1));
	}

	/* Update the elf file to update the offsets into the file. */
	if (elf_update(e, ELF_C_NULL) < 0)
		errx(EXIT_FAILURE, "elf_update() failed: %s", elf_errmsg(-1));

	/*
	 * Refer to the data segments from program headers because that's
	 * where core files hold this information.
	 */
	section = NULL;

	for (i = 0; i < ranges_len; ++i) {
		if ((section = elf_nextscn(e, section)) == NULL)
			errx(EXIT_FAILURE, "Couldn't get all the sections");

		if (phdr != gelf_getphdr(e, i, phdr))
			errx(EXIT_FAILURE, "gelf_getphdr() failed: %s",
				elf_errmsg(-1));

		if (&shdr != gelf_getshdr(section, &shdr))
			errx(EXIT_FAILURE, "gelf_getshdr() failed: %s",
				elf_errmsg(-1));

		data = elf_getdata(section, NULL);
		phdr->p_type = PT_LOAD;
		phdr->p_flags = ranges[i].prot;
		/* data offset is from where the section starts. */
		phdr->p_offset = shdr.sh_offset + data->d_off;
		phdr->p_vaddr = ranges[i].vaddr;
		phdr->p_paddr = 0; /* Leave paddr as 0 */
		phdr->p_filesz = ranges[i].filelen;
		phdr->p_memsz = ranges[i].rangelen;
		phdr->p_align = pagesize;
		if (gelf_update_phdr(e, i, phdr) == 0)
			errx(EXIT_FAILURE, "gelf_update_phdr() failed: %s",
				elf_errmsg(-1));
	}

	/* Program headers header */
	if (phdr != gelf_getphdr(e, ranges_len, phdr))
		errx(EXIT_FAILURE, "gelf_getphdr() failed: %s",
			elf_errmsg(-1));
	phdr->p_type = PT_PHDR;
	phdr->p_offset = ehdr->e_phoff;
	phdr->p_filesz = gelf_fsize(e, ELF_T_PHDR, 1 , EV_CURRENT);

	elf_flagphdr(e, ELF_C_SET, ELF_F_DIRTY);

	if (elf_update(e, ELF_C_WRITE) < 0)
		errx(EXIT_FAILURE, "elf_update() failed: %s", elf_errmsg(-1));

	if (fvc_close(fvc) != 0)
		errx(EXIT_FAILURE, "Couldn't close the vmcore \"%s\": %s",
			vmcore, fvc_geterr(fvc));

	for (i = 0; i < ranges_len; ++i)
		free(ranges[i].buf);
	free(ranges);
	elf_end(e);
	close(fd);
}

