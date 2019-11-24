#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "libelf/libelf.h"
#include "libelf/gelf.h"


// TODO: better error messages
const char *FILESUFFIX = ".shrinked";

typedef struct range{
	unsigned long long from;
	unsigned long long to;
} Range;

struct chain;

typedef struct chain{
	Range data;
	struct chain *next;
} Chain;

/*
 * Get element from list by index.
 * Returns NULL if there is no entry with correspondig index.
 */
Chain *get(Chain *start, unsigned int index) {
	Chain *tmp = start;
	while (index > 0) {
		if (tmp == NULL)
			return NULL;
		tmp = tmp->next;
		index--;
	}
	return tmp;
}

/*
 * Insert element elem in list start. List is sorted.
 * Returns -1 if ranges overlap.
 */
int insert(Chain *start, Chain *elem) {
	if (elem->data.from < start->data.from) {
		if (elem->data.to > start->data.from)
			//ranges overlap
			return -1;

		Range tmp;
		tmp.from = elem->data.from;
		tmp.to = elem->data.to;

		elem->next = start->next;
		start->next = elem;
		elem->data.from = start->data.from;
		elem->data.to = start->data.to;
		start->data.from = tmp.from;
		start->data.to = tmp.to;
	}
	else {
		Chain *ahead = start->next;		// FIXME: better name
		Chain *following = start;		// FIXME: better name
		while (ahead != NULL && elem->data.from < ahead->data.from) {
			following = ahead;
			ahead = ahead->next;
		}
		if (following->data.to > elem->data.from)
			// ranges overlap
			return -1;
		if (ahead != NULL && elem->data.to > ahead->data.from)
			// ranges overlap
			return -1;

		following->next = elem;
		elem->next = ahead;
	}
	return 0;
}

// FIXME: comments
void deleteList(Chain *start) {
	Chain *tmp = start->next;
	free(start);
	while (tmp != NULL) {
		start = tmp;
		tmp = tmp->next;
		free(start);
	}
}

int main(int argc, char **argv) {
	Chain *ranges = NULL;

	int opt;
	while ((opt = getopt(argc, argv, "hk:")) != -1) {
		switch (opt) {
			case 'k':
				// you can't have a label on a declaration
				// because of it's C
				;
				// FIXME: variable names
				// FIXME: error messages
				char *p = strpbrk(optarg, ":-");
				if (p == NULL) {
					error(0, 0, "Invalid remove argument '%s' - ignoring!", optarg);
				} else {
					errno = 0;
					Chain *tmp = malloc(sizeof(Chain));
					tmp->next = NULL;
					char *f = NULL;
					tmp->data.from = strtoull(optarg, &f, 0);
					char *t = NULL;
					tmp->data.to = strtoull(p + 1, &t, 0);
					if ((tmp->data.from == 0 && f == optarg) || (tmp->data.to == 0 && t == p + 1) || errno != 0 || f != p || *t != '\0') {
						error(0, 0, "Remove argument '%s' not parsable - ignoring!", optarg);
					} else {
						if (*p == ':') {
							tmp->data.to += tmp->data.from;
						}
						if (tmp->data.to <= tmp->data.from) {
							error(0, 0, "Invalid range '%s' - ignoring!", optarg);
						} else {
							if (ranges == NULL)
								ranges = tmp;
							else
								insert(ranges, tmp);
						}
					}
				}
				break;
			case 'h':
			case '?':
				printf("Usage: shrinkelf [-h] INPUT\n");
				printf("   -h        Print this help\n");
				printf("   -k RANGE  Keep given RANGE. Accepted formats are\n");
				printf("               'START-END' exclusive END\n");
				printf("               'START:LEN' LEN in bytes\n");
				printf("             with common prefixes for base.\n");
				printf("   INPUT     Input file\n");
				return 0;
			default:
				error(EXIT_FAILURE, 0,
				      "Invalid parameter '-%c', abort (use -h for help).",
				      opt);
		}
	}

	if (optind >= argc)
		error(EXIT_FAILURE, 0, "No input file (use -h for help)");

	// Debugging - FIXME: remove!
	Chain *tmp = ranges;
	while (tmp != NULL) {
		printf("Range from %llu to %llu\n", tmp->data.from, tmp->data.to);
		tmp = tmp->next;
	}
	free(ranges);

	char *filename = argv[optind];

	// libelf-library won't work if you don't tell it the ELF version
	if (elf_version(EV_CURRENT) == EV_NONE)
		error(EXIT_FAILURE, 0, "ELF library initialization failed: %s",
		      elf_errmsg(-1));

	int srcfd;	// file descriptor of source file
	if ((srcfd = open(filename, O_RDONLY)) < 0)
		error(EXIT_FAILURE, errno, "unable to open %s", filename);
	Elf *srce;	// ELF representation of source file
	if ((srce = elf_begin(srcfd, ELF_C_READ, NULL)) == NULL) {
		error(0, 0, "could not retrieve ELF structures from source file: %s",
		      elf_errmsg(-1));
		goto err_free_srcfd;
	}

	// TODO: maybe let user choose filename for new file
	size_t fnamesz = strlen(filename) + strlen(FILESUFFIX) + 1;
	if (fnamesz <= strlen(filename) || fnamesz <= strlen(FILESUFFIX)) {
		error(0, 0, "resulting output filename too long");
		goto err_free_srce;
	}
	// filename of new file
	char *dstfname = malloc(fnamesz);
	if(dstfname == NULL) {
		error(0, errno, "unable to allocate memory for new filename");
		goto err_free_srce;
	}
	strncpy(dstfname, filename, strlen(filename));
	strncat(dstfname, FILESUFFIX, strlen(FILESUFFIX));

	int dstfd;	// file descriptor of new file
	if ((dstfd = open(dstfname, O_WRONLY | O_CREAT, 0777)) < 0) {
		error(0, errno, "unable to open %s", dstfname);
		goto err_free_dstfname;
	}
	Elf *dste;	// ELF representation of new file
	if ((dste = elf_begin(dstfd, ELF_C_WRITE, NULL)) == NULL) {
		error(0, 0, "could not create ELF structures for new file: %s",
		      elf_errmsg(-1));
		goto err_free_dstfd;
	}

	if (elf_flagelf(dste, ELF_C_SET, ELF_F_LAYOUT) == 0) {
		error(0, 0, "elf_flagelf() failed: %s.", elf_errmsg(-1));
		goto err_free_dste;
	}

//-----------------------------------------------------------------------------
// Copy executable header
//-----------------------------------------------------------------------------
	int elfclass;		//ELF class of source file
	if ((elfclass = gelf_getclass(srce)) == ELFCLASSNONE) {
		error(0, 0, "could not retrieve ELF class from source file");
		goto err_free_dste;
	}
	// executable header of source file
	GElf_Ehdr *srcehdr = malloc(sizeof(GElf_Ehdr));
	if(srcehdr == NULL) {
		error(0, errno, "unable to allocate memory for executable header of source file");
		goto err_free_dste;
	}
	if (gelf_getehdr(srce, srcehdr) == NULL) {
		error(0, 0, "could not retrieve executable header from source file: %s",
		      elf_errmsg(-1));
		goto err_free_srcehdr;
	}
	// executable header of new file
	GElf_Ehdr *dstehdr = malloc(sizeof(GElf_Ehdr));
	if(dstehdr == NULL) {
		error(0, errno, "unable to allocate memory for executable header of new file");
		goto err_free_srcehdr;
	}
	/*
	 * gelf_newehdr sets automatically the magic numbers of an ELF header,
	 * the EI_CLASS byte according to elfclass, the EI_VERSION byte and
	 * e_version to the version you told the library to use.
	 *
	 * The EI_DATA byte is set to ELFDATANONE, e_machine to EM_NONE and
	 * e_type to ELF_K_NONE.
	 *
	 * Other members are set to zero. This includes the EI_OSABI and
	 * EI_ABIVERSION bytes.
	 */
	if ((dstehdr = gelf_newehdr(dste, elfclass)) == NULL) {
		error(0, 0, "could not create executable header of new file: %s",
		      elf_errmsg(-1));
		goto err_free_dstehdr;
	}
	dstehdr->e_ident[EI_DATA] = srcehdr->e_ident[EI_DATA];
	dstehdr->e_ident[EI_OSABI] = srcehdr->e_ident[EI_OSABI];
	dstehdr->e_ident[EI_ABIVERSION] = srcehdr->e_ident[EI_ABIVERSION];
	dstehdr->e_machine = srcehdr->e_machine;
	dstehdr->e_type = srcehdr->e_type;
	dstehdr->e_flags = srcehdr->e_flags;
	// TODO: better wording
	// fall back for not adjusting this attributes
	dstehdr->e_shoff = srcehdr->e_shoff;
	dstehdr->e_phoff = srcehdr->e_phoff;
	dstehdr->e_shstrndx = srcehdr->e_shstrndx;
	dstehdr->e_entry = srcehdr->e_entry;
	if (gelf_update_ehdr(dste, dstehdr) == 0) {
		error(0, 0, "could not update ELF structures (Header): %s",
		      elf_errmsg(-1));
		goto err_free_dstehdr;
	}

	// FIXME: comments!
//-----------------------------------------------------------------------------
// Copy sections and section headers
//-----------------------------------------------------------------------------
	size_t scnnum = 0;		// number of sections in source file
	if (elf_getshdrnum(srce, &scnnum) != 0) {
		error(0, 0, "could not retrieve number of sections from source file: %s",
		      elf_errmsg(-1));
		goto err_free_dstehdr;
	}
	// storage for current section header of source file
	GElf_Shdr *srcshdr = malloc(sizeof(GElf_Shdr));
	if (srcshdr == NULL) {
		error(0, errno, "unable to allocate memory for source shdr structure");
		goto err_free_dstehdr;
	}
	// storage for current section header of new file
	GElf_Shdr *dstshdr = malloc(sizeof(GElf_Shdr));
	if (dstshdr == NULL) {
		error(0, errno, "unable to allocate memory for new shdr structure");
		free(srcshdr);
		goto err_free_srcshdr;
	}
	Elf_Scn *srcscn = NULL;		// current section of source file
	// lib creates section 0 automatically
	for (size_t i = 1; i < scnnum; i++) {
		srcscn = elf_getscn(srce, i);
		if (srcscn == NULL)
			// FIXME: error message
			goto err_free_dstshdr;

		if (gelf_getshdr(srcscn, srcshdr) == NULL) {
			error(0, 0, "could not retrieve source shdr structure for section %lu: %s",
			      i, elf_errmsg(-1));
			goto err_free_dstshdr;
		}
		Elf_Scn *dstscn = elf_newscn(dste);
		if (dstscn == NULL) {
			error(0, 0, "could not create section %lu: %s", i,
			      elf_errmsg(-1));
			goto err_free_dstshdr;
		}
		if (gelf_getshdr(dstscn, dstshdr) == NULL) {
			error(0, 0, "could not retrieve new shdr structure for section %lu: %s",
			      i, elf_errmsg(-1));
			goto err_free_dstshdr;
		}

		// current data of current section of source file
		Elf_Data *srcdata = NULL;
		while ((srcdata = elf_getdata(srcscn, srcdata)) != NULL) {
			Elf_Data *dstdata = elf_newdata(dstscn);
			if (dstdata == NULL) {
				error(0, 0, "could not add data to section %lu: %s",
				      i, elf_errmsg(-1));
				goto err_free_dstshdr;
			}
			dstdata->d_align = srcdata->d_align;
			dstdata->d_type = srcdata->d_type;
			dstdata->d_version = srcdata->d_version;
			dstdata->d_buf = srcdata->d_buf;
			dstdata->d_off = srcdata->d_off;
			dstdata->d_size = srcdata->d_size;
		}

		dstshdr->sh_info = srcshdr->sh_info;
		dstshdr->sh_name = srcshdr->sh_name;
		dstshdr->sh_type = srcshdr->sh_type;
		dstshdr->sh_addr = srcshdr->sh_addr;
		dstshdr->sh_flags = srcshdr->sh_flags;
		dstshdr->sh_offset = srcshdr->sh_offset;
		dstshdr->sh_size = srcshdr->sh_size;
		dstshdr->sh_addralign = srcshdr->sh_addralign;
		dstshdr->sh_entsize = srcshdr->sh_entsize;
		dstshdr->sh_link = srcshdr->sh_link;

		if (gelf_update_shdr(dstscn, dstshdr) == 0) {
			error(0, 0, "could not update ELF structures (Sections): %s",
			      elf_errmsg(-1));
			goto err_free_dstshdr;
		}
	}

	// FIXME: comments
//-----------------------------------------------------------------------------
// Copy program headers
//-----------------------------------------------------------------------------
	size_t phdrnum = 0;		// number of segments in source file
	if (elf_getphdrnum(srce, &phdrnum) != 0) {
		error(0, 0, "could not retrieve number of segments from source file: %s",
		      elf_errmsg(-1));
		goto err_free_dstshdr;
	}
	GElf_Phdr *srcphdr = malloc(sizeof(GElf_Phdr));
	if (srcphdr == NULL) {
		error(0, errno, "ran out of memory");
		goto err_free_dstshdr;
	}
	GElf_Phdr *dstphdrs = gelf_newphdr(dste, phdrnum);
	if (dstphdrs == NULL) {
		error(0, 0, "gelf_newphdr() failed: %s", elf_errmsg(-1));
		goto err_free_srcphdr;
	}
	for (size_t i = 0; i < phdrnum; i++) {
		if (gelf_getphdr(srce, i, srcphdr) == NULL) {
			error(0, 0, "could not retrieve source phdr structure %lu: %s",
			      i, elf_errmsg(-1));
			goto err_free_srcphdr;
		}
		dstphdrs[i].p_type = srcphdr->p_type;
		dstphdrs[i].p_offset = srcphdr->p_offset;
		dstphdrs[i].p_vaddr = srcphdr->p_vaddr;
		dstphdrs[i].p_paddr = srcphdr->p_paddr;
		dstphdrs[i].p_filesz = srcphdr->p_filesz;
		dstphdrs[i].p_memsz = srcphdr->p_memsz;
		dstphdrs[i].p_flags = srcphdr->p_flags;
		dstphdrs[i].p_align = srcphdr->p_align;
	}
	if (elf_update(dste, ELF_C_WRITE) == -1) {
		error(0, 0, "could not update ELF structures: %s",
		      elf_errmsg(-1));
		goto err_free_srcphdr;
	}

	// tidy up
	free(srcphdr);
	free(dstshdr);
	free(srcshdr);
	free(dstehdr);
	free(srcehdr);
	elf_end(dste);
	if (close(dstfd) < 0) {
		error(0, errno, "unable to close %s", dstfname);
		goto err_free_dstfname;
	}
	free(dstfname);
	elf_end(srce);
	if (close(srcfd) < 0)
		error(EXIT_FAILURE, errno, "unable to close %s", filename);

	return 0;

err_free_srcphdr:
	free(srcphdr);
err_free_dstshdr:
	free(dstshdr);
err_free_srcshdr:
	free(srcshdr);
err_free_dstehdr:
	free(dstehdr);
err_free_srcehdr:
	free(srcehdr);
err_free_dste:
	elf_end(dste);
err_free_dstfd:
	if (close(dstfd) < 0)
		error(0, errno, "unable to close %s", dstfname);
err_free_dstfname:
	free(dstfname);
err_free_srce:
	elf_end(srce);
err_free_srcfd:
	if (close(srcfd) < 0)
		error(0, errno, "unable to close %s", filename);
	exit(EXIT_FAILURE);
}
