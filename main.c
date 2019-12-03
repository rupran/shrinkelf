#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

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
 * Insert element elem in list start. List start is sorted.
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
		// between this two elements elem needs to be inserted
		Chain *ahead = start->next;
		Chain *following = start;
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

/*
 * Frees a complete list.
 */
void deleteList(Chain *start) {
	Chain *tmp = start->next;
	free(start);
	while (tmp != NULL) {
		start = tmp;
		tmp = tmp->next;
		free(start);
	}
}

/*
 * compute the ranges to keep per section and store them in array dest
 */
int computeSectionRanges(Elf *src, Chain *ranges, Chain *dest, size_t section_number) {
	// storage for current section header of source file
	GElf_Shdr *srcshdr = malloc(sizeof(GElf_Shdr));
	if (srcshdr == NULL) {
		error(0, errno, "unable to allocate memory for source shdr structure");
		return -1;
	}
	Elf_Scn *srcscn = NULL;			// current section of source file
	Chain *current = ranges;		// current range to process
	for (size_t i = 0; i < section_number; i++) {
		srcscn = elf_getscn(src, i);
		if (srcscn == NULL) {
			error(0, 0, "could not retrieve source section structure for section %lu: %s", i, elf_errmsg(-1));
			goto err_free_srcshdr2;
		}

		if (gelf_getshdr(srcscn, srcshdr) == NULL) {
			error(0, 0, "could not retrieve source shdr structure for section %lu: %s", i, elf_errmsg(-1));
			goto err_free_srcshdr2;
		}
		if (srcshdr->sh_type == SHT_NOBITS)
			// no content in section => no bits to keep
			continue;
/*
		if (current->data.to > srcshdr->sh_offset) {
			// data to keep
			Chain *tmp = malloc(sizeof(Chain));
			if (tmp == NULL) {
				error(0, errno, "unable to allocate memory");
				goto err_free_srcshdr2;
			}

			tmp->next = NULL;
			if (current->data.from < srcshdr->sh_offset)
				tmp->data.from = 0;
			else
				tmp->data.from = current->data.from - srcshdr->sh_offset;

			if (current->data.to < srcshdr->sh_offset + srcshdr->sh_size) {
				tmp->data.to = current->data.to - srcshdr->sh_offset;
				current = current->next;
			}
			// FIXME: nächstes Listenelement
			else
				tmp->data.to = srcshdr->sh_size;

			if (dest[i].data.to == 0) {
				dest[i].data.from = tmp->data.from;
				dest[i].data.to = tmp->data.to;
			}
			else
				insert(&dest[i], tmp);
		}
*/

		while (current->data.to <= srcshdr->sh_offset + srcshdr->sh_size) {
			Chain *tmp = malloc(sizeof(Chain));
			if (tmp == NULL) {
				error(0, errno, "unable to allocate memory");
				goto err_free_srcshdr2;
			}
			tmp->next = NULL;

			if (current->data.from < srcshdr->sh_offset)
				tmp->data.from = 0;
			else
				tmp->data.from = current->data.from - srcshdr->sh_offset;

			if (current->data.to < srcshdr->sh_offset + srcshdr->sh_size)
				tmp->data.to = current->data.to - srcshdr->sh_offset;
			else
				tmp->data.to = srcshdr->sh_size;

			if (dest[i].data.to == 0) {
				dest[i].data.from = tmp->data.from;
				dest[i].data.to = tmp->data.to;
				free(tmp);
			}
			else
				insert(&dest[i], tmp);
			current = current->next;
		}

		if (current->data.from < srcshdr->sh_offset + srcshdr->sh_size) {
			Chain *tmp = malloc(sizeof(Chain));
			if (tmp == NULL) {
				error(0, errno, "unable to allocate memory");
				goto err_free_srcshdr2;
			}
			tmp->next = NULL;

			if (current->data.from < srcshdr->sh_offset)
				tmp->data.from = 0;
			else
				tmp->data.from = current->data.from - srcshdr->sh_offset;
			printf("current: %llu, srchdr: %lu\n", current->data.from, srcshdr->sh_offset);
			tmp->data.to = srcshdr->sh_size;

			if (dest[i].data.to == 0) {
				dest[i].data.from = tmp->data.from;
				dest[i].data.to = tmp->data.to;
				free(tmp);
			}
			else
				insert(&dest[i], tmp);
		}
	}
	printf("\n\n\n");
	return 0;

err_free_srcshdr2:
	free(srcshdr);
	return -1;
}

int main(int argc, char **argv) {
	// FIXME: free this list
	Chain *ranges = NULL;

	int opt;
	while ((opt = getopt(argc, argv, "hk:")) != -1) {
		switch (opt) {
			case 'k':
				// you can't have a label on a declaration
				// because of it's C
				;
				char *split = strpbrk(optarg, ":-");
				if (split == NULL) {
					error(0, 0, "Invalid range argument '%s' - ignoring!", optarg);
				} else {
					errno = 0;
					Chain *tmp = malloc(sizeof(Chain));
					if (tmp == NULL)
						error(EXIT_FAILURE, errno, "Unable to allocate memory");
					tmp->next = NULL;
					char *from = NULL;
					errno = 0;
					tmp->data.from = strtoull(optarg, &from, 0);
					if (tmp->data.from == ULLONG_MAX && errno != 0)
						error(0, errno, "First part of range argument '%s' not parsable - ignoring!", optarg);
					char *to = NULL;
					tmp->data.to = strtoull(split + 1, &to, 0);
					if (tmp->data.to == ULLONG_MAX && errno != 0)
						error(0, errno, "Second part of range argument '%s' not parsable - ignoring!", optarg);
					if ((tmp->data.from == 0 && from == optarg) || (tmp->data.to == 0 && to == split + 1) || errno != 0 || from != split || *to != '\0') {
						error(0, 0, "Range argument '%s' not parsable - ignoring!", optarg);
					} else {
						if (*split == ':') {
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
				error(EXIT_FAILURE, 0, "Invalid parameter '-%c', abort (use -h for help).", opt);
		}
	}

	if (optind >= argc)
		error(EXIT_FAILURE, 0, "No input file (use -h for help)");

	// XXX: Debugging - remove!
	Chain *tmp = ranges;
	while (tmp != NULL) {
		printf("Range from %llu to %llu\n", tmp->data.from, tmp->data.to);
		tmp = tmp->next;
	}

	char *filename = argv[optind];

	// libelf-library won't work if you don't tell it the ELF version
	if (elf_version(EV_CURRENT) == EV_NONE)
		error(EXIT_FAILURE, 0, "ELF library initialization failed: %s", elf_errmsg(-1));

	int srcfd;	// file descriptor of source file
	if ((srcfd = open(filename, O_RDONLY)) < 0)
		error(EXIT_FAILURE, errno, "unable to open %s", filename);
	Elf *srce;	// ELF representation of source file
	if ((srce = elf_begin(srcfd, ELF_C_READ, NULL)) == NULL) {
		error(0, 0, "could not retrieve ELF structures from source file: %s", elf_errmsg(-1));
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
		error(0, 0, "could not create ELF structures for new file: %s", elf_errmsg(-1));
		goto err_free_dstfd;
	}

	if (elf_flagelf(dste, ELF_C_SET, ELF_F_LAYOUT) == 0) {
		error(0, 0, "elf_flagelf() failed: %s.", elf_errmsg(-1));
		goto err_free_dste;
	}

//-----------------------------------------------------------------------------
// Copy executable header
//-----------------------------------------------------------------------------
	int elfclass;		// ELF class of source file
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
		error(0, 0, "could not retrieve executable header from source file: %s", elf_errmsg(-1));
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
		error(0, 0, "could not create executable header of new file: %s", elf_errmsg(-1));
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
		error(0, 0, "could not update ELF structures (Header): %s", elf_errmsg(-1));
		goto err_free_dstehdr;
	}

	// FIXME: comments!
//-----------------------------------------------------------------------------
// Copy sections and section headers
//-----------------------------------------------------------------------------
	size_t scnnum = 0;		// number of sections in source file
	if (elf_getshdrnum(srce, &scnnum) != 0) {
		error(0, 0, "could not retrieve number of sections from source file: %s", elf_errmsg(-1));
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
	tmp = ranges;		// XXX: prototype removing
	Chain *section_ranges = calloc(scnnum, sizeof(Chain));
	if (section_ranges == NULL) {
		error(0, errno, "unable to allocate memory");
		goto err_free_dstshdr;
	}
	if (computeSectionRanges(srce, ranges, section_ranges, scnnum) != 0) {
		goto err_free_dstshdr;
	}

	// XXX: Debug
	for (size_t i = 0; i < scnnum; i++) {
		printf("Section %lu\n", i);
		Chain *tmp = &section_ranges[i];
		while (tmp != NULL) {
			printf("Range from %llx to %llx\n", tmp->data.from, tmp->data.to);
			tmp = tmp->next;
		}
		printf("\n");
	}
	// lib creates section 0 automatically
	for (size_t i = 1; i < scnnum; i++) {
		srcscn = elf_getscn(srce, i);
		if (srcscn == NULL)
			error(0, 0, "could not retrieve source section %lu: %s", i, elf_errmsg(-1));
			goto err_free_dstshdr;

		if (gelf_getshdr(srcscn, srcshdr) == NULL) {
			error(0, 0, "could not retrieve source shdr structure for section %lu: %s", i, elf_errmsg(-1));
			goto err_free_dstshdr;
		}
		Elf_Scn *dstscn = elf_newscn(dste);
		if (dstscn == NULL) {
			error(0, 0, "could not create section %lu: %s", i, elf_errmsg(-1));
			goto err_free_dstshdr;
		}
		if (gelf_getshdr(dstscn, dstshdr) == NULL) {
			error(0, 0, "could not retrieve new shdr structure for section %lu: %s", i, elf_errmsg(-1));
			goto err_free_dstshdr;
		}

		size_t section_offset = srcshdr->sh_offset;	// XXX: prototype removing
		// current data of current section of source file
		Elf_Data *srcdata = NULL;
		while ((srcdata = elf_getdata(srcscn, srcdata)) != NULL) {
			while (tmp->data.from <= section_offset + srcdata->d_off + srcdata->d_size) {		// XXX: prototype removing - FIXME: removing last bytes
				// XXX: prototype removing
				ssize_t buffer_offset = tmp->data.from - (section_offset + srcdata->d_off);
				if (buffer_offset < 0)
					buffer_offset = 0;
				if ((srcdata->d_off + buffer_offset) % srcdata->d_align != 0) {
					error(0, 0, "section %lu is misaligned by %lu bytes - aborting", i, (srcdata->d_off + buffer_offset) % srcdata->d_align);
					goto err_free_dstshdr;
				}
				// FIXME: buffer size depends on old size, range to keep and offset in the databuffer
				size_t buffer_size = tmp->data.to - tmp->data.from;
				if (buffer_size > srcdata->d_size)
					buffer_size = srcdata->d_size;

				Elf_Data *dstdata = elf_newdata(dstscn);
				if (dstdata == NULL) {
					error(0, 0, "could not add data to section %lu: %s", i, elf_errmsg(-1));
					goto err_free_dstshdr;
				}
				dstdata->d_align = srcdata->d_align;
				dstdata->d_type = srcdata->d_type;
				dstdata->d_version = srcdata->d_version;
				// XXX: prototype removing - FIXME: alignment
				dstdata->d_buf = srcdata->d_buf + buffer_offset;
				dstdata->d_off = srcdata->d_off + buffer_offset;
				dstdata->d_size = buffer_size;
				// XXX: prototype removing
				if (tmp->data.to > section_offset + srcdata->d_off + srcdata->d_size)
					break;
				tmp = tmp->next;
			}
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
			error(0, 0, "could not update ELF structures (Sections): %s", elf_errmsg(-1));
			goto err_free_dstshdr;
		}
	}

	// FIXME: comments
//-----------------------------------------------------------------------------
// Copy program headers
//-----------------------------------------------------------------------------
	size_t phdrnum = 0;		// number of segments in source file
	if (elf_getphdrnum(srce, &phdrnum) != 0) {
		error(0, 0, "could not retrieve number of segments from source file: %s", elf_errmsg(-1));
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
			error(0, 0, "could not retrieve source phdr structure %lu: %s", i, elf_errmsg(-1));
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
		error(0, 0, "could not update ELF structures: %s", elf_errmsg(-1));
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
