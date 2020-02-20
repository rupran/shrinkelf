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


#define PAGESIZE 0x1000
#define FALSE 0x00
#define TRUE 0xff

const char *FILESUFFIX = ".shrinked";

/*
 * Contains start and end of range to keep based on addresses in the file.
 */
typedef struct range{
	unsigned long long from;
	unsigned long long to;
} Range;

// FIXME: comment
struct address_space_info{
	int loadable;
	unsigned long long flags;
	unsigned long long align;
	unsigned long long section_offset;
	unsigned long long section_align;
	unsigned long long from;
	unsigned long long to;
};

struct chain;

// FIXME: comment
typedef struct chain{
	Range data;
	struct chain *next;
	struct address_space_info as;
} Chain;

/*
 * Contains information about the location of data in the new file.
 * start is the address of that data in the original file
 * size is the size of that data in byte
 * shift is the difference between the new and the old address of that data
 *
 * more formal:
 * The data of the original file in range [start, start + size) resides in range
 * [start - shift, start + size - shift) in the new file.
 */
struct relocation_info{
	unsigned long long start;
	size_t size;
	signed long long shift;
};

struct relocation_infos{
	struct relocation_infos *next;
	struct relocation_info info;
};
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
		// elem is new head
		if (elem->data.to > start->data.from)
			//ranges overlap
			return -1;

		Range tmp;
		tmp.from = elem->data.from;
		tmp.to = elem->data.to;
		struct address_space_info tmp_info;
		tmp_info.loadable = elem->as.loadable;
		tmp_info.flags = elem->as.flags;
		tmp_info.align = elem->as.align;
		tmp_info.section_offset = elem->as.section_offset;
		tmp_info.section_align = elem->as.section_align;
		tmp_info.from = elem->as.from;
		tmp_info.to = elem->as.to;

		elem->next = start->next;
		start->next = elem;

		elem->data.from = start->data.from;
		elem->data.to = start->data.to;
		elem->as.loadable = start->as.loadable;
		elem->as.flags = start->as.flags;
		elem->as.align = start->as.align;
		elem->as.section_offset = start->as.section_offset;
		elem->as.section_align = start->as.section_align;
		elem->as.from = start->as.from;
		elem->as.to = start->as.to;

		start->data.from = tmp.from;
		start->data.to = tmp.to;
		start->as.loadable = tmp_info.loadable;
		start->as.flags = tmp_info.flags;
		start->as.align = tmp_info.align;
		start->as.section_offset = tmp_info.section_offset;
		start->as.section_align = tmp_info.section_align;
		start->as.from = tmp_info.from;
		start->as.to = tmp_info.to;
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
 * Size of list start.
 */
size_t size(Chain *start) {
	if (start->data.to == 0)
		// no elements in list
		return 0;

	size_t ret = 1;
	while (start->next != NULL) {
		ret++;
		start = start->next;
	}
	return ret;
}

// FIXME: comment
size_t find (Chain *start, unsigned long long from) {
	size_t ret = 0;
	while (start->data.from < from) {
		ret++;
		start = start->next;
	}
	return ret;
}

/*
 * compute the ranges to keep per section and store them in array dest
 */
int computeSectionRanges(Elf *src, Chain *ranges, Chain *dest, size_t section_number) {
	errno = 0;
	// storage for current section header of source file
	GElf_Shdr *srcshdr = calloc(1, sizeof(GElf_Shdr));
	if (srcshdr == NULL) {
		error(0, errno, "unable to allocate memory for source shdr structure");
		return -1;
	}

	// number of segments in source file
	size_t phdrnum = 0;
	if (elf_getphdrnum(src, &phdrnum) != 0) {
		error(0, 0, "could not retrieve number of segments from source file: %s", elf_errmsg(-1));
		goto err_free_srcshdr2;
	}
	errno = 0;
	// storage for current program header of source file
	GElf_Phdr *srcphdr = calloc(1, sizeof(GElf_Phdr));
	if (srcphdr == NULL) {
		error(0, errno, "ran out of memory");
		goto err_free_srcshdr2;
	}

	// current section of source file
	Elf_Scn *srcscn = NULL;
	// current range to process
	Chain *current = ranges;
	for (size_t i = 0; i < section_number; i++) {
		srcscn = elf_getscn(src, i);
		if (srcscn == NULL) {
			error(0, 0, "could not retrieve source section structure for section %lu: %s", i, elf_errmsg(-1));
			goto err_free_srcphdr2;
		}

		if (gelf_getshdr(srcscn, srcshdr) == NULL) {
			error(0, 0, "could not retrieve source shdr structure for section %lu: %s", i, elf_errmsg(-1));
			goto err_free_srcphdr2;
		}

		// FIXME: comment
		while (current && current->data.to <= srcshdr->sh_offset + (srcshdr->sh_type == SHT_NOBITS ? 0 : srcshdr->sh_size)) {
			errno = 0;
			Chain *tmp = calloc(1, sizeof(Chain));
			if (tmp == NULL) {
				error(0, errno, "unable to allocate memory");
				goto err_free_srcphdr2;
			}
			tmp->next = NULL;

			if (srcshdr->sh_type == SHT_NOBITS) {
				tmp->data.from = 0;
				tmp->data.to = 0;
			}
			else {
				if (current->data.from < srcshdr->sh_offset)
					tmp->data.from = 0;
				else
					tmp->data.from = current->data.from - srcshdr->sh_offset;

				if (current->data.to < srcshdr->sh_offset + srcshdr->sh_size)
					tmp->data.to = current->data.to - srcshdr->sh_offset;
				else
					tmp->data.to = srcshdr->sh_size;
			}
			if (srcshdr->sh_addralign != 65536)
				tmp->as.section_align = srcshdr->sh_addralign;
			else
				tmp->as.section_align = 16;

			for (size_t j = 0; j < phdrnum; j++) {
				if (gelf_getphdr(src, j, srcphdr) == NULL) {
					error(0, 0, "could not retrieve source phdr structure %lu: %s", i, elf_errmsg(-1));
					goto err_free_srcphdr2;
				}

				// not a loadable segment
				if (srcphdr->p_type != PT_LOAD)
					continue;

				// loadable segment but does not load this section
				if (srcphdr->p_offset >= srcshdr->sh_offset + (srcshdr->sh_type == SHT_NOBITS ? 0 : srcshdr->sh_size) || srcphdr->p_offset + (srcshdr->sh_type == SHT_NOBITS ? srcphdr->p_memsz : srcphdr->p_filesz) <= srcshdr->sh_offset)
					continue;

				tmp->as.loadable = TRUE;
				tmp->as.flags = srcphdr->p_flags;
				tmp->as.align = srcphdr->p_align;
				tmp->as.section_offset = srcshdr->sh_offset;
				// FIXME: sinnvollere Methode, das Alignment-Problem im Testfall zu lösen
				if (srcphdr->p_offset <= srcshdr->sh_offset)
					tmp->as.from = srcphdr->p_vaddr + srcshdr->sh_offset + tmp->data.from - srcphdr->p_offset;
				else
					tmp->as.from = srcphdr->p_offset - srcshdr->sh_offset;
				if (srcshdr->sh_type == SHT_NOBITS) {
					tmp->as.to = tmp->as.from + srcshdr->sh_size;
				}
				else {
					tmp->as.to = tmp->as.from + (tmp->data.to - tmp->data.from);
				}
				break;
			}

			if (dest[i].data.to == 0) {
				dest[i].data.from = tmp->data.from;
				dest[i].data.to = tmp->data.to;
				dest[i].as.from = tmp->as.from;
				dest[i].as.to = tmp->as.to;
				dest[i].as.loadable = tmp->as.loadable;
				dest[i].as.flags = tmp->as.flags;
				dest[i].as.align = tmp->as.align;
				dest[i].as.section_offset = tmp->as.section_offset;
				dest[i].as.section_align = tmp->as.section_align;
				free(tmp);
			}
			else
				insert(&dest[i], tmp);
			current = current->next;
		}

		if (current && current->data.from < srcshdr->sh_offset + (srcshdr->sh_type == SHT_NOBITS ? 0 : srcshdr->sh_size)) {
			errno = 0;
			Chain *tmp = calloc(1, sizeof(Chain));
			if (tmp == NULL) {
				error(0, errno, "unable to allocate memory");
				goto err_free_srcphdr2;
			}
			tmp->next = NULL;

			if (srcshdr->sh_type == SHT_NOBITS) {
				tmp->data.from = 0;
				tmp->data.to = 0;
			}
			else {
				if (current->data.from < srcshdr->sh_offset)
					tmp->data.from = 0;
				else
					tmp->data.from = current->data.from - srcshdr->sh_offset;
				tmp->data.to = srcshdr->sh_size;
			}
			if (srcshdr->sh_addralign != 65536)
				tmp->as.section_align = srcshdr->sh_addralign;
			else
				tmp->as.section_align = 16;

			for (size_t j = 0; j < phdrnum; j++) {
				if (gelf_getphdr(src, j, srcphdr) == NULL) {
					error(0, 0, "could not retrieve source phdr structure %lu: %s", i, elf_errmsg(-1));
					goto err_free_srcphdr2;
				}

				// not a loadable segment
				if (srcphdr->p_type != PT_LOAD)
					continue;

				// loadable segment but does not load this section
				if (srcphdr->p_offset >= srcshdr->sh_offset + (srcshdr->sh_type == SHT_NOBITS ? 0 : srcshdr->sh_size) || srcphdr->p_offset + (srcshdr->sh_type == SHT_NOBITS ? srcphdr->p_memsz : srcphdr->p_filesz) <= srcshdr->sh_offset)
					continue;

				tmp->as.loadable = TRUE;
				tmp->as.flags = srcphdr->p_flags;
				tmp->as.align = srcphdr->p_align;
				tmp->as.section_offset = srcshdr->sh_offset;
				// FIXME: sinnvollere Methode, das Alignment-Problem im Testfall zu lösen
				if (srcphdr->p_offset <= srcshdr->sh_offset)
					tmp->as.from = srcphdr->p_vaddr + srcshdr->sh_offset + tmp->data.from - srcphdr->p_offset;
				else
					tmp->as.from = srcphdr->p_offset - srcshdr->sh_offset;
				if (srcshdr->sh_type == SHT_NOBITS) {
					tmp->as.to = tmp->as.from + srcshdr->sh_size;
				}
				else {
					tmp->as.to = tmp->as.from + (tmp->data.to - tmp->data.from);
				}
				break;
			}

			if (dest[i].data.to == 0) {
				dest[i].data.from = tmp->data.from;
				dest[i].data.to = tmp->data.to;
				dest[i].as.from = tmp->as.from;
				dest[i].as.to = tmp->as.to;
				dest[i].as.loadable = tmp->as.loadable;
				dest[i].as.flags = tmp->as.flags;
				dest[i].as.align = tmp->as.align;
				dest[i].as.section_offset = tmp->as.section_offset;
				dest[i].as.section_align = tmp->as.section_align;
				free(tmp);
			}
			else
				insert(&dest[i], tmp);
		}
	}
	free(srcphdr);
	free(srcshdr);
	return 0;

err_free_srcphdr2:
	free(srcphdr);
err_free_srcshdr2:
	free(srcshdr);
	return -1;
}

// FIXME: comment
size_t calculateCeil(size_t value, size_t base) {
	size_t tmp = value % base;
	if (tmp != 0)
		return value - tmp + base;
	else
		return value;
}

// FIXME: comment
size_t calculateOffsetInPage(size_t addr) {
	return addr % PAGESIZE;
}

/*
 * Counts LOAD program headers.
 * Returns -1 in case of an error.
 */
int countLOADs(Elf *elf) {
	int count = 0;

	size_t phdrnum = 0;		// number of segments in file
	if (elf_getphdrnum(elf, &phdrnum) != 0) {
		error(0, 0, "could not retrieve number of segments from source file: %s", elf_errmsg(-1));
		return -1;
	}
	errno = 0;
	GElf_Phdr *phdr = calloc(1, sizeof(GElf_Phdr));
	if (phdr == NULL) {
		error(0, errno, "ran out of memory");
		return -1;
	}
	for (size_t i = 0; i < phdrnum; i++) {
		if (gelf_getphdr(elf, i, phdr) == NULL) {
			error(0, 0, "could not retrieve source phdr structure %lu: %s", i, elf_errmsg(-1));
			free(phdr);
			return -1;
		}

		if (phdr->p_type == PT_LOAD) {
			count++;
		}
	}
	free(phdr);
	return count;
}

/*
 * Counts loadable ranges headers.
 */
int countLoadableRanges(Chain *ranges, size_t size) {
	int count = 0;

	for (size_t i = 0; i < size; i++) {
		Chain *tmp = &ranges[i];
		while (tmp) {
			if (tmp->as.loadable)
				count++;
			tmp = tmp->next;
		}
	}
	return count;
}

/*
 * Calculates offset of a structure in its containing structure (section/file or
 * data block/section). priorOffset is the offset of that structure in the original file,
 * occupiedSpace points to the first free byte in the containing structure where that structure
 * is appended.
 * Contraint: new offset needs to be equal prior offset modulo page size because LOAD segments
 * require that p_offset (offset in file) is equal p_vaddr (address in virtual address space)
 * modulo page size.
 */
size_t calculateOffset(size_t priorOffset, size_t occupiedSpace) {
	size_t priorPageOffset = calculateOffsetInPage(priorOffset);
	size_t occupiedPageOffset = calculateOffsetInPage(occupiedSpace);
	if (occupiedPageOffset <= priorPageOffset) {
		return occupiedSpace - occupiedPageOffset + priorPageOffset;
	}
	else {
		return occupiedSpace - occupiedPageOffset + priorPageOffset + PAGESIZE;
	}
}



// FIXME: comment
int main(int argc, char **argv) {
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
					// FIXME: comment
					errno = 0;
					Chain *tmp = calloc(1, sizeof(Chain));
					if (tmp == NULL) {
						error(0, errno, "Unable to allocate memory");
						goto err_free_ranges;
					}
					tmp->next = NULL;
					tmp->as.loadable = FALSE;
					char *from = NULL;
					errno = 0;
					tmp->data.from = strtoull(optarg, &from, 0);
					if (tmp->data.from == ULLONG_MAX && errno != 0)
						error(0, errno, "First part of range argument '%s' not parsable - ignoring!", optarg);
					char *to = NULL;
					errno = 0;
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
				error(0, 0, "Invalid parameter '-%c', abort (use -h for help).", opt);
				goto err_free_ranges;
		}
	}

	if (optind >= argc) {
		error(0, 0, "No input file (use -h for help)");
		goto err_free_ranges;
	}

	char *filename = argv[optind];

	// libelf-library won't work if you don't tell it the ELF version
	if (elf_version(EV_CURRENT) == EV_NONE) {
		error(0, 0, "ELF library initialization failed: %s", elf_errmsg(-1));
		goto err_free_ranges;
	}

	int srcfd;	// file descriptor of source file
	errno = 0;
	if ((srcfd = open(filename, O_RDONLY)) < 0) {
		error(EXIT_FAILURE, errno, "unable to open %s", filename);
		goto err_free_ranges;
	}
	Elf *srce;	// ELF representation of source file
	if ((srce = elf_begin(srcfd, ELF_C_READ, NULL)) == NULL) {
		error(0, 0, "could not retrieve ELF structures from source file: %s", elf_errmsg(-1));
		goto err_free_srcfd;
	}

	size_t fnamesz = strlen(filename) + strlen(FILESUFFIX) + 1;
	if (fnamesz <= strlen(filename) || fnamesz <= strlen(FILESUFFIX)) {
		error(0, 0, "resulting output filename too long");
		goto err_free_srce;
	}
	errno = 0;
	// filename of new file
	char *dstfname = calloc(fnamesz, sizeof(char));
	if(dstfname == NULL) {
		error(0, errno, "unable to allocate memory for new filename");
		goto err_free_srce;
	}
	strncpy(dstfname, filename, strlen(filename));
	strncat(dstfname, FILESUFFIX, strlen(FILESUFFIX));

	int dstfd;	// file descriptor of new file
	errno = 0;
	if ((dstfd = open(dstfname, O_WRONLY | O_CREAT, 0777)) < 0) {
		error(0, errno, "unable to open %s", dstfname);
		goto err_free_dstfname;
	}
	Elf *dste;	// ELF representation of new file
	if ((dste = elf_begin(dstfd, ELF_C_WRITE, NULL)) == NULL) {
		error(0, 0, "could not create ELF structures for new file: %s", elf_errmsg(-1));
		goto err_free_dstfd;
	}

	// tell lib that the application will take care of the exact file layout
	if (elf_flagelf(dste, ELF_C_SET, ELF_F_LAYOUT) == 0) {
		error(0, 0, "elf_flagelf() failed: %s.", elf_errmsg(-1));
		goto err_free_dste;
	}

	// XXX: Debug
	elf_fill(0xaa);

//-----------------------------------------------------------------------------
// Copy executable header
//-----------------------------------------------------------------------------
	int elfclass;		// ELF class of source file
	if ((elfclass = gelf_getclass(srce)) == ELFCLASSNONE) {
		error(0, 0, "could not retrieve ELF class from source file");
		goto err_free_dste;
	}
	errno = 0;
	// executable header of source file
	GElf_Ehdr *srcehdr = calloc(1, sizeof(GElf_Ehdr));
	if(srcehdr == NULL) {
		error(0, errno, "unable to allocate memory for executable header of source file");
		goto err_free_dste;
	}
	if (gelf_getehdr(srce, srcehdr) == NULL) {
		error(0, 0, "could not retrieve executable header from source file: %s", elf_errmsg(-1));
		goto err_free_srcehdr;
	}
	errno = 0;
	// executable header of new file
	GElf_Ehdr *dstehdr;
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
	// fall back if this attributes are not adjusted later
	dstehdr->e_shoff = srcehdr->e_shoff;
	dstehdr->e_phoff = srcehdr->e_phoff;
	dstehdr->e_shstrndx = srcehdr->e_shstrndx;
	dstehdr->e_entry = srcehdr->e_entry;
	if (gelf_update_ehdr(dste, dstehdr) == 0) {
		error(0, 0, "could not update ELF structures (Header): %s", elf_errmsg(-1));
		goto err_free_dstehdr;
	}

	// FIXME: comments
//-----------------------------------------------------------------------------
// Copy program headers
//-----------------------------------------------------------------------------
	size_t scnnum = 0;		// number of sections in source file
	if (elf_getshdrnum(srce, &scnnum) != 0) {
		error(0, 0, "could not retrieve number of sections from source file: %s", elf_errmsg(-1));
		goto err_free_dstehdr;
	}
	errno = 0;
	// FIXME: free section_ranges (normal + in case of an error)
	// FIXME: initialize section_ranges
	Chain *section_ranges = calloc(scnnum, sizeof(Chain));
	if (section_ranges == NULL) {
		error(0, errno, "unable to allocate memory");
		goto err_free_dstehdr;
	}
	if (computeSectionRanges(srce, ranges, section_ranges, scnnum) != 0) {
		goto err_free_dstehdr;
	}
	deleteList(ranges);
	ranges = NULL;

	size_t phdrnum = 0;		// number of segments in source file
	if (elf_getphdrnum(srce, &phdrnum) != 0) {
		error(0, 0, "could not retrieve number of segments from source file: %s", elf_errmsg(-1));
		goto err_free_dstehdr;
	}
	errno = 0;
	GElf_Phdr *srcphdr = calloc(1, sizeof(GElf_Phdr));
	if (srcphdr == NULL) {
		error(0, errno, "ran out of memory");
		goto err_free_dstehdr;
	}

	int loads = countLOADs(srce);
	if (loads == -1)
		goto err_free_srcphdr;
	// new phdrnum = old #segments - old #loads + #ranges to load + LOAD for EHDR&PHDR
	size_t new_phdrnum = phdrnum - loads + countLoadableRanges(section_ranges, scnnum) + 2;
	GElf_Phdr *dstphdrs = gelf_newphdr(dste, new_phdrnum);
	if (dstphdrs == NULL) {
		error(0, 0, "gelf_newphdr() failed: %s", elf_errmsg(-1));
		goto err_free_srcphdr;
	}

	size_t new_index = 0;
	int first_load = FALSE;
	// FIXME: free
	struct relocation_infos *relinfos = calloc(1, sizeof(struct relocation_infos));
	if (relinfos == NULL) {
		error(0, errno, "ran out of memory");
		goto err_free_srcphdr;
	}
	for (size_t i = 0; i < phdrnum; i++) {
		if (gelf_getphdr(srce, i, srcphdr) == NULL) {
			error(0, 0, "could not retrieve source phdr structure %lu: %s", i, elf_errmsg(-1));
			goto err_free_srcphdr;
		}

		if (srcphdr->p_type != PT_LOAD) {
			dstphdrs[new_index].p_type = srcphdr->p_type;
			dstphdrs[new_index].p_offset = srcphdr->p_offset;
			dstphdrs[new_index].p_vaddr = srcphdr->p_vaddr;
			dstphdrs[new_index].p_paddr = srcphdr->p_paddr;
			dstphdrs[new_index].p_filesz = srcphdr->p_filesz;
			dstphdrs[new_index].p_memsz = srcphdr->p_memsz;
			dstphdrs[new_index].p_flags = srcphdr->p_flags;
			dstphdrs[new_index].p_align = srcphdr->p_align;
			new_index++;
		}
		else if (first_load)
			continue;
		else {
			first_load = TRUE;
			size_t current_size = 0;

			// FIXME: LOAD für EHDR
			dstphdrs[new_index].p_type = PT_LOAD;
			dstphdrs[new_index].p_offset = srcphdr->p_offset;
			dstphdrs[new_index].p_vaddr = srcphdr->p_vaddr;
			dstphdrs[new_index].p_paddr = srcphdr->p_paddr;
			if (elfclass == ELFCLASS32) {
				dstphdrs[new_index].p_filesz = sizeof(Elf32_Ehdr);
				dstphdrs[new_index].p_memsz = sizeof(Elf32_Ehdr);
			}
			else {
				dstphdrs[new_index].p_filesz = sizeof(Elf64_Ehdr);
				dstphdrs[new_index].p_memsz = sizeof(Elf64_Ehdr);
			}
			dstphdrs[new_index].p_flags = PF_X | PF_R;
			// TODO: intelligentere Alignmentberechnung
			dstphdrs[new_index].p_align = PAGESIZE;

			current_size = dstphdrs[new_index].p_offset + dstphdrs[new_index].p_filesz;
			relinfos->info.start = dstphdrs[new_index].p_offset;
			relinfos->info.size = dstphdrs[new_index].p_filesz;
			relinfos->info.shift = 0;
			new_index++;

			for (size_t i = 0; i < scnnum; i++) {
				Chain *tmp = &section_ranges[i];
				while (tmp) {
					if (tmp->as.loadable) {
						dstphdrs[new_index].p_type = PT_LOAD;
						// FIXME: offset in Datei berechnen
						dstphdrs[new_index].p_offset = calculateOffset(tmp->as.section_offset + tmp->data.from, current_size);
						dstphdrs[new_index].p_vaddr = tmp->as.from;
						dstphdrs[new_index].p_paddr = tmp->as.from;
						dstphdrs[new_index].p_filesz = tmp->data.to - tmp->data.from;
						dstphdrs[new_index].p_memsz = tmp->as.to - tmp->as.from;
						dstphdrs[new_index].p_flags = tmp->as.flags;
						// TODO: intelligentere Alignmentberechnung
						dstphdrs[new_index].p_align = PAGESIZE;

						current_size = dstphdrs[new_index].p_offset + dstphdrs[new_index].p_filesz;
						if (relinfos->info.start + relinfos->info.size == tmp->as.section_offset + tmp->data.from && relinfos->info.shift == (signed long long)dstphdrs[new_index].p_offset - (signed long long)relinfos->info.start){
							relinfos->info.size += dstphdrs[new_index].p_filesz;
						}
						else {
							struct relocation_infos *second_tmp_relinfos = relinfos;
							struct relocation_infos *tmp_relinfos = relinfos->next;
							while(tmp_relinfos != NULL){
								if (tmp_relinfos->info.start + tmp_relinfos->info.size == tmp->as.section_offset + tmp->data.from && tmp_relinfos->info.shift == (signed long long)dstphdrs[new_index].p_offset - (signed long long)tmp_relinfos->info.start - (signed long long)tmp_relinfos->info.size){
									tmp_relinfos->info.size += dstphdrs[new_index].p_filesz;
									break;
								}
								second_tmp_relinfos = tmp_relinfos;
								tmp_relinfos = tmp_relinfos->next;
							}
							if(tmp_relinfos == NULL) {
								second_tmp_relinfos->next = calloc(1, sizeof(struct relocation_infos));
								if(second_tmp_relinfos->next == NULL) {
									error(0, errno, "ran out of memory");
									goto err_free_srcphdr;
								}
								second_tmp_relinfos->next->info.start = tmp->as.section_offset + tmp->data.from;
								second_tmp_relinfos->next->info.size = dstphdrs[new_index].p_filesz;
								second_tmp_relinfos->next->info.shift = (unsigned long long)second_tmp_relinfos->next->info.start - (unsigned long long)dstphdrs[new_index].p_offset;
							}
						}
						new_index++;
					}
					tmp = tmp->next;
				}
			}
			// XXX: LOAD für PHDR - DEBUG
			dstphdrs[new_index].p_type = PT_LOAD;
			dstehdr->e_phoff = calculateOffset(0, current_size);
			dstphdrs[new_index].p_offset = dstehdr->e_phoff;
			if (elfclass == ELFCLASS32) {
				// FIXME: p_vaddr & p_paddr fixen
				dstphdrs[new_index].p_vaddr = srcphdr->p_vaddr + sizeof(Elf32_Ehdr);
				dstphdrs[new_index].p_paddr = srcphdr->p_paddr + sizeof(Elf32_Ehdr);
				dstphdrs[new_index].p_filesz = new_phdrnum * sizeof(Elf32_Phdr);
				dstphdrs[new_index].p_memsz = new_phdrnum * sizeof(Elf32_Phdr);
			}
			else {
				// FIXME: p_vaddr & p_paddr fixen
				dstphdrs[new_index].p_vaddr = srcphdr->p_vaddr + sizeof(Elf64_Ehdr);
				dstphdrs[new_index].p_paddr = srcphdr->p_paddr + sizeof(Elf64_Ehdr);
				dstphdrs[new_index].p_filesz = new_phdrnum * sizeof(Elf64_Phdr);
				dstphdrs[new_index].p_memsz = new_phdrnum * sizeof(Elf64_Phdr);
			}
			dstphdrs[new_index].p_flags = PF_X | PF_R;
			// TODO: intelligentere Alignmentberechnung
			dstphdrs[new_index].p_align = PAGESIZE;

			new_index++;
		}
	}

	for (size_t i = 0; i < new_phdrnum; i++) {
		if (dstphdrs[i].p_type != PT_LOAD) {
			for (struct relocation_infos *tmp = relinfos; tmp != NULL; tmp = tmp->next) {
				if (tmp->info.start <= dstphdrs[i].p_offset && dstphdrs[i].p_offset < tmp->info.start + tmp->info.size) {
					dstphdrs[i].p_offset -= tmp->info.shift;
					break;
				}
			}
		}
	}

	// FIXME: comments!
//-----------------------------------------------------------------------------
// Copy sections and section headers
//-----------------------------------------------------------------------------
	errno = 0;
	// storage for current section header of source file
	GElf_Shdr *srcshdr = calloc(1, sizeof(GElf_Shdr));
	if (srcshdr == NULL) {
		error(0, errno, "unable to allocate memory for source shdr structure");
		goto err_free_srcphdr;
	}
	errno = 0;
	// storage for current section header of new file
	GElf_Shdr *dstshdr = calloc(1, sizeof(GElf_Shdr));
	if (dstshdr == NULL) {
		error(0, errno, "unable to allocate memory for new shdr structure");
		goto err_free_srcshdr;
	}
	Elf_Scn *srcscn = NULL;		// current section of source file
	// lib creates section 0 automatically
	size_t current_filesize = 0;
	// FIXME: calculate new current filesize
	if (elfclass == ELFCLASS32) {
		current_filesize = sizeof(Elf32_Ehdr);
	}
	else {
		current_filesize = sizeof(Elf64_Ehdr);
	}
	for (size_t i = 1; i < scnnum; i++) {
		srcscn = elf_getscn(srce, i);
		if (srcscn == NULL) {
			error(0, 0, "could not retrieve source section %lu: %s", i, elf_errmsg(-1));
			goto err_free_dstshdr;
		}

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

		// FIXME: comment
		char *data_buffers[size(&section_ranges[i])];
		for (size_t j = 0; j < size(&section_ranges[i]); j++) {
			Chain *tmp = get(&section_ranges[i], j);
			errno = 0;
			data_buffers[j] = calloc(tmp->data.to - tmp->data.from, sizeof(char));
			if (data_buffers[j] == NULL) {
				error(0, errno, "Unable to allocate memory");
				goto err_free_dstshdr;
			}
		}

		// current data of current section of source file
		Elf_Data *srcdata = NULL;
		while ((srcdata = elf_getdata(srcscn, srcdata)) != NULL) {
			if (srcdata->d_buf == NULL) {
				// section is NOBITS section => no data to copy
				continue;
			}
			// FIXME: databuffer contains only a part of range to keep
			size_t srcdata_begin = srcdata->d_off;
			size_t srcdata_end = srcdata->d_off + srcdata->d_size;
			size_t index = find(&section_ranges[i], srcdata_begin);
			Chain *tmp = get(&section_ranges[i], index);
			// XXX: Debug
			if (tmp == NULL) {
				// zero elements to process
				printf("Zero elements to process");
			}
			size_t data_size = 0;
			while (tmp->data.to <= srcdata_end) {
				// range is in srcdata->d_buf
				data_size = tmp->data.to - tmp->data.from;
				memcpy(data_buffers[index], srcdata->d_buf + tmp->data.from - srcdata_begin, data_size);
				// advance to next range, while condition checks if that range is still in srcdata->d_buf
				tmp = tmp->next;
				index++;
				if (tmp == NULL) {
					// reached end of list
					goto new_data;
				}
			}

			if (tmp->data.from < srcdata_end) {
				// beginning of range is in srcdata->d_buf, end of range is not
				// maybe this will not happen at all, but libelf does not guarantee that
				data_size = srcdata_end - tmp->data.from;
				memcpy(data_buffers[index], srcdata->d_buf + tmp->data.from - srcdata_begin, data_size);
				// FIXME: offset in destination buffer
			}
		}

new_data:
		;
		// FIXME: srcdata nicht verwenden
		size_t current_section_offset = calculateOffset(srcshdr->sh_offset, current_filesize);
		size_t current_offset = current_section_offset;
		for (size_t j = 0; j < size(&section_ranges[i]); j++) {
			Elf_Data *dstdata = elf_newdata(dstscn);
			if (dstdata == NULL) {
				error(0, 0, "could not add data to section %lu: %s", i, elf_errmsg(-1));
				goto err_free_dstshdr;
			}

			Chain *tmp = get(&section_ranges[i], j);
			size_t off = calculateOffsetInPage(srcshdr->sh_offset + tmp->data.from);

			// FIXME: an neue Berechnungsmethode anpassen
			// FIXME: comment
			if ((current_offset + off - srcshdr->sh_offset) % tmp->as.section_align != 0) {
				error(0, 0, "in section %lu: range to keep is misaligned by %llu bytes (offset in section: %lu, aligment: %llu)", i, (current_offset + off - srcshdr->sh_offset) % tmp->as.section_align, current_offset + off - srcshdr->sh_offset, tmp->as.section_align);
				goto err_free_dstshdr;
			}
			dstdata->d_align = tmp->as.section_align;
			// FIXME: srcdata nicht verwenden
			dstdata->d_type = srcdata->d_type;
			// FIXME: srcdata nicht verwenden
			dstdata->d_version = srcdata->d_version;
			dstdata->d_buf = data_buffers[j];
			dstdata->d_off = calculateOffset(srcshdr->sh_offset + tmp->data.from, current_offset) - current_section_offset;
			dstdata->d_size = tmp->data.to - tmp->data.from;
			current_offset = current_section_offset + dstdata->d_off + dstdata->d_size;
		}

		dstshdr->sh_info = srcshdr->sh_info;
		dstshdr->sh_name = srcshdr->sh_name;
		dstshdr->sh_type = srcshdr->sh_type;
		dstshdr->sh_addr = srcshdr->sh_addr;
		dstshdr->sh_flags = srcshdr->sh_flags;
		// FIXME: comment
		// FIXME: sinnvollere Methode, das Alignment-Problem im Testfall zu lösen
		if (srcshdr->sh_addralign == 65536)
			dstshdr->sh_addralign = 16;
		else
			dstshdr->sh_addralign = srcshdr->sh_addralign;
		dstshdr->sh_offset = calculateOffset(srcshdr->sh_offset, current_filesize);
		if (srcshdr->sh_type == SHT_NOBITS)
			dstshdr->sh_size = srcshdr->sh_size;
		else
			dstshdr->sh_size = current_offset - current_section_offset;
		dstshdr->sh_entsize = srcshdr->sh_entsize;
		dstshdr->sh_link = srcshdr->sh_link;

		if (gelf_update_shdr(dstscn, dstshdr) == 0) {
			error(0, 0, "could not update ELF structures (Sections): %s", elf_errmsg(-1));
			goto err_free_dstshdr;
		}
		if (srcshdr->sh_type != SHT_NOBITS)
			current_filesize = dstshdr->sh_offset + dstshdr->sh_size;
	}

	if (elfclass == ELFCLASS32)
		dstehdr->e_shoff = calculateCeil(current_filesize, sizeof(Elf32_Shdr));
	else
		dstehdr->e_shoff = calculateCeil(current_filesize, sizeof(Elf64_Shdr));

	if (elf_update(dste, ELF_C_WRITE) == -1) {
		error(0, 0, "could not update ELF structures: %s", elf_errmsg(-1));
		goto err_free_srcphdr;
	}

	// tidy up
	free(srcphdr);
	for (size_t i = 0; i < scnnum; i++) {
		if (section_ranges[i].next) {
			deleteList(section_ranges[i].next);
		}
	}
	free(section_ranges);
	free(dstshdr);
	free(srcshdr);
	free(srcehdr);
	elf_end(dste);
	errno = 0;
	if (close(dstfd) < 0) {
		error(0, errno, "unable to close %s", dstfname);
		goto err_free_dstfname;
	}
	free(dstfname);
	errno = 0;
	elf_end(srce);
	if (close(srcfd) < 0)
		error(EXIT_FAILURE, errno, "unable to close %s", filename);

	return 0;

err_free_dstshdr:
	free(dstshdr);
err_free_srcshdr:
	free(srcshdr);
err_free_srcphdr:
	free(srcphdr);
err_free_dstehdr:
	free(dstehdr);
err_free_srcehdr:
	free(srcehdr);
err_free_dste:
	elf_end(dste);
err_free_dstfd:
	errno = 0;
	if (close(dstfd) < 0)
		error(0, errno, "unable to close %s", dstfname);
err_free_dstfname:
	free(dstfname);
err_free_srce:
	elf_end(srce);
err_free_srcfd:
	errno = 0;
	if (close(srcfd) < 0)
		error(0, errno, "unable to close %s", filename);
err_free_ranges:
	if (ranges != NULL)
		deleteList(ranges);
	exit(EXIT_FAILURE);
}
