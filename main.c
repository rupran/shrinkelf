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

// FIXME: comment
typedef struct range{
	unsigned long long from;
	unsigned long long to;
} Range;

// FIXME: comment
struct address_space_info{
	int loadable;
	unsigned long long flags;
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
		tmp_info.from = elem->as.from;
		tmp_info.to = elem->as.to;

		elem->next = start->next;
		start->next = elem;

		elem->data.from = start->data.from;
		elem->data.to = start->data.to;
		elem->as.loadable = start->as.loadable;
		elem->as.flags = start->as.flags;
		elem->as.from = start->as.from;
		elem->as.to = start->as.to;

		start->data.from = tmp.from;
		start->data.to = tmp.to;
		start->as.loadable = tmp_info.loadable;
		start->as.flags = tmp_info.flags;
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
	// storage for current section header of source file
	errno = 0;
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

		// FIXME: comment
		while (current && current->data.to <= srcshdr->sh_offset + srcshdr->sh_size) {
			errno = 0;
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

			// FIXME: address_space_info befüllen

			// TODO: warum teste ich dest[i].data.to auf 0? Um festzustellen,
			// ob die Liste leer ist?
			if (dest[i].data.to == 0) {
				dest[i].data.from = tmp->data.from;
				dest[i].data.to = tmp->data.to;
				// FIXME: as befüllen
				free(tmp);
			}
			else
				insert(&dest[i], tmp);
			current = current->next;
		}

		if (current && current->data.from < srcshdr->sh_offset + srcshdr->sh_size) {
			errno = 0;
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
			tmp->data.to = srcshdr->sh_size;

			// FIXME: address_space_info befüllen

			// TODO: warum teste ich dest[i].data.to auf 0? Um festzustellen,
			// ob die Liste leer ist?
			if (dest[i].data.to == 0) {
				dest[i].data.from = tmp->data.from;
				dest[i].data.to = tmp->data.to;
				// FIXME: as befüllen
				free(tmp);
			}
			else
				insert(&dest[i], tmp);
		}
	}
	return 0;

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
					Chain *tmp = malloc(sizeof(Chain));
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
	char *dstfname = malloc(fnamesz);
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
	GElf_Ehdr *srcehdr = malloc(sizeof(GElf_Ehdr));
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
	// fall back if this attributes are not adjusted later
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
	errno = 0;
	// storage for current section header of source file
	GElf_Shdr *srcshdr = malloc(sizeof(GElf_Shdr));
	if (srcshdr == NULL) {
		error(0, errno, "unable to allocate memory for source shdr structure");
		goto err_free_dstehdr;
	}
	errno = 0;
	// storage for current section header of new file
	GElf_Shdr *dstshdr = malloc(sizeof(GElf_Shdr));
	if (dstshdr == NULL) {
		error(0, errno, "unable to allocate memory for new shdr structure");
		free(srcshdr);
		goto err_free_srcshdr;
	}
	Elf_Scn *srcscn = NULL;		// current section of source file
	errno = 0;
	// FIXME: free section_ranges (normal + in case of an error)
	// FIXME: initialize section_ranges
	Chain *section_ranges = calloc(scnnum, sizeof(Chain));
	if (section_ranges == NULL) {
		error(0, errno, "unable to allocate memory");
		goto err_free_dstshdr;
	}
	if (computeSectionRanges(srce, ranges, section_ranges, scnnum) != 0) {
		goto err_free_dstshdr;
	}
	deleteList(ranges);
	ranges = NULL;

	// lib creates section 0 automatically
	size_t current_filesize = 0;
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

		if (i == 1)
			current_filesize = srcshdr->sh_offset;

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
			// FIXME: databuffer contains only a part of range to keep
			size_t srcdata_begin = srcdata->d_off;
			size_t srcdata_end = srcdata->d_off + srcdata->d_size;
			size_t index = find(&section_ranges[i], srcdata_begin);
			Chain *tmp = get(&section_ranges[i], index);
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
		size_t current_offset = srcshdr->sh_offset - (srcshdr->sh_offset % PAGESIZE);
		size_t current_size = 0;
		for (size_t j = 0; j < size(&section_ranges[i]); j++) {
			Elf_Data *dstdata = elf_newdata(dstscn);
			if (dstdata == NULL) {
				error(0, 0, "could not add data to section %lu: %s", i, elf_errmsg(-1));
				goto err_free_dstshdr;
			}

			Chain *tmp = get(&section_ranges[i], j);
			size_t off = calculateOffsetInPage(srcshdr->sh_offset + tmp->data.from);

			// FIXME: sinnvollere Methode, das Alignment-Problem im Testfall zu lösen
			if (srcdata->d_align != 65536 && (current_offset + off - srcshdr->sh_offset) % srcdata->d_align != 0) {
				error(0, 0, "in section %lu: range to keep is misaligned by %lu bytes (offset in section: %lu, aligment: %lu)", i, (current_offset + off - srcshdr->sh_offset) % srcdata->d_align, current_offset + off - srcshdr->sh_offset, srcdata->d_align);
				goto err_free_dstshdr;
			}
			// FIXME: sinnvollere Methode, das Alignment-Problem im Testfall zu lösen
			if (srcdata->d_align == 65536)
				dstdata->d_align = 16;
			else
				dstdata->d_align = srcdata->d_align;
			dstdata->d_type = srcdata->d_type;
			dstdata->d_version = srcdata->d_version;
			dstdata->d_buf = data_buffers[j];
			dstdata->d_off = current_offset + off - srcshdr->sh_offset;
			dstdata->d_size = tmp->data.to - tmp->data.from;
			if (current_offset < srcshdr->sh_offset)
				// first data range
				current_size = dstdata->d_size;
			else
				current_size = current_offset + dstdata->d_size - srcshdr->sh_offset;
			current_offset = calculateCeil(current_offset + off + dstdata->d_size, PAGESIZE);
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
		dstshdr->sh_offset = calculateCeil(current_filesize, dstshdr->sh_addralign);
		if (srcshdr->sh_type == SHT_NOBITS)
			dstshdr->sh_size = srcshdr->sh_size;
		else
			dstshdr->sh_size = current_size;
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

	// FIXME: comments
//-----------------------------------------------------------------------------
// Copy program headers
//-----------------------------------------------------------------------------
	size_t phdrnum = 0;		// number of segments in source file
	if (elf_getphdrnum(srce, &phdrnum) != 0) {
		error(0, 0, "could not retrieve number of segments from source file: %s", elf_errmsg(-1));
		goto err_free_dstshdr;
	}
	errno = 0;
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
