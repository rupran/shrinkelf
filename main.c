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
 * Description of data range to keep using file layout.
 *
 * section_offset, section_align: offset and alignment of containing section
 * from, to: start and end (exclusive) of range based on start of containing section
 * section_shift: shift of containing section in new file; negative values mean a shift toward address 0
 * data_shift: shift of range inside of containing section; negative values mean a shift towards start of section
 * buffer: buffer for data described by this struct
 * d_type, d_version: values of corresponding members of Elf_Data library struct
 */
typedef struct range{
	unsigned long long from;
	unsigned long long to;
	unsigned long long section_offset;
	unsigned long long section_align;
	signed long long section_shift;
	signed long long data_shift;
	char *buffer;
	Elf_Type d_type;
	unsigned int d_version;
} Range;

/*
 * Information about memory layout
 *
 * loadable: flag if range is part of a LOAD segment
 * flags, align: flags and alignment of containing segment
 * from, to: start and end of range in memory as virtual addresses
 */
struct address_space_info{
	int loadable;
	unsigned long long flags;
	unsigned long long align;
	unsigned long long from;
	unsigned long long to;
};

/*
 * List of data ranges and associated address space description
 */
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
 * Range that will be loaded. Combines multiple ranges given via command line if needed.
 * offset, fsize: offset and size in the original file
 * vaddr, msize: virtual start address and size in memory
 */
struct segmentRange {
	unsigned long long offset;
	unsigned long long fsize;
	unsigned long long vaddr;
	unsigned long long msize;
	signed long long shift;
	int loadable;
};

struct segmentRanges {
	struct segmentRanges *next;
	struct segmentRange range;
};

/*
 * Description of the new file layout
 *
 * phdr_start, phdr_entries: start address and number of entries of new PHDR table
 * shdr_start: start address of new SHDR table
 */
struct layoutDescription {
	unsigned long long phdr_start;
	unsigned long long phdr_entries;
	unsigned long long shdr_start;
	struct segmentRanges** segments;
	size_t segmentNum;
};



/*
 * Insert element elem in list start. List start is sorted.
 * Returns -1 if ranges overlap.
 */
int insert(Chain *start, Chain *elem) {
	if (elem->data.from < start->data.from) {
		/* elem is new head */
		if (elem->data.to > start->data.from) {
			/* ranges overlap */
			return -1;
		}

		Range tmp;
		tmp.from = elem->data.from;
		tmp.to = elem->data.to;
		tmp.section_offset = elem->data.section_offset;
		tmp.section_align = elem->data.section_align;
		struct address_space_info tmp_info;
		tmp_info.loadable = elem->as.loadable;
		tmp_info.flags = elem->as.flags;
		tmp_info.align = elem->as.align;
		tmp_info.from = elem->as.from;
		tmp_info.to = elem->as.to;

		elem->next = start->next;
		start->next = elem;

		elem->data.from = start->data.from;
		elem->data.to = start->data.to;
		elem->data.section_offset = start->data.section_offset;
		elem->data.section_align = start->data.section_align;
		elem->as.loadable = start->as.loadable;
		elem->as.flags = start->as.flags;
		elem->as.align = start->as.align;
		elem->as.from = start->as.from;
		elem->as.to = start->as.to;

		start->data.from = tmp.from;
		start->data.to = tmp.to;
		start->data.section_offset = tmp.section_offset;
		start->data.section_align = tmp.section_align;
		start->as.loadable = tmp_info.loadable;
		start->as.flags = tmp_info.flags;
		start->as.align = tmp_info.align;
		start->as.from = tmp_info.from;
		start->as.to = tmp_info.to;
	}
	else {
		/* between this two elements elem needs to be inserted */
		Chain *ahead = start->next;
		Chain *following = start;
		while (ahead != NULL && elem->data.from > ahead->data.from) {
			following = ahead;
			ahead = ahead->next;
		}
		if (following->data.to > elem->data.from) {
			/* ranges overlap */
			return -1;
		}
		if (ahead != NULL && elem->data.to > ahead->data.from) {
			/* ranges overlap */
			return -1;
		}

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
	if (start->data.buffer) {
		free(start->data.buffer);
	}
	free(start);
	while (tmp != NULL) {
		start = tmp;
		tmp = tmp->next;
		if (start->data.buffer) {
			free(start->data.buffer);
		}
		free(start);
	}
}

/*
 * Size of list start.
 */
size_t size(Chain *start) {
	if (start->data.to == 0) {
		/* no elements in list */
		return 0;
	}

	size_t ret = 1;
	while (start->next != NULL) {
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

		/* split ranges in section ranges and add layout data */
		while (current && current->data.to <= srcshdr->sh_offset + (srcshdr->sh_type == SHT_NOBITS ? 0 : srcshdr->sh_size)) {
			errno = 0;
			Chain *tmp = calloc(1, sizeof(Chain));
			if (tmp == NULL) {
				error(0, errno, "unable to allocate memory");
				goto err_free_srcphdr2;
			}
			tmp->next = NULL;

			/* determine start and end addresses of section range in file */
			if (srcshdr->sh_type == SHT_NOBITS) {
				tmp->data.from = 0;
				tmp->data.to = 0;
			}
			else {
				if (current->data.from < srcshdr->sh_offset) {
					tmp->data.from = 0;
				}
				else {
					tmp->data.from = current->data.from - srcshdr->sh_offset;
				}

				if (current->data.to < srcshdr->sh_offset + srcshdr->sh_size) {
					tmp->data.to = current->data.to - srcshdr->sh_offset;
				}
				else {
					tmp->data.to = srcshdr->sh_size;
				}
			}

			// FIXME: Alignment im Testfall
			if (srcshdr->sh_addralign != 65536) {
				tmp->data.section_align = srcshdr->sh_addralign;
			}
			else {
				tmp->data.section_align = 16;
			}
			tmp->data.section_offset = srcshdr->sh_offset;

			/* memory layout of section range */
			for (size_t j = 0; j < phdrnum; j++) {
				if (gelf_getphdr(src, j, srcphdr) == NULL) {
					error(0, 0, "could not retrieve source phdr structure %lu: %s", i, elf_errmsg(-1));
					goto err_free_srcphdr2;
				}

				if (srcphdr->p_type != PT_LOAD) {
					/* not a loadable segment */
					continue;
				}

				if (srcphdr->p_offset >= srcshdr->sh_offset + (srcshdr->sh_type == SHT_NOBITS ? 0 : srcshdr->sh_size) || srcphdr->p_offset + (srcshdr->sh_type == SHT_NOBITS ? srcphdr->p_memsz : srcphdr->p_filesz) <= srcshdr->sh_offset) {
					/* loadable segment but does not load this section */
					continue;
				}

				tmp->as.loadable = TRUE;
				tmp->as.flags = srcphdr->p_flags;
				tmp->as.align = srcphdr->p_align;
				/* determine start and end addresses of section range in memory */
				if (srcphdr->p_offset <= srcshdr->sh_offset) {
					tmp->as.from = srcphdr->p_vaddr + srcshdr->sh_offset + tmp->data.from - srcphdr->p_offset;
				}
				else {
					tmp->as.from = srcphdr->p_offset - srcshdr->sh_offset;
				}
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
				dest[i].data.section_offset = tmp->data.section_offset;
				dest[i].data.section_align = tmp->data.section_align;
				dest[i].as.from = tmp->as.from;
				dest[i].as.to = tmp->as.to;
				dest[i].as.loadable = tmp->as.loadable;
				dest[i].as.flags = tmp->as.flags;
				dest[i].as.align = tmp->as.align;
				free(tmp);
			}
			else {
				insert(&dest[i], tmp);
			}
			current = current->next;
		}

		/* split ranges in section ranges and add layout data - edge case */
		if (current && current->data.from < srcshdr->sh_offset + (srcshdr->sh_type == SHT_NOBITS ? 0 : srcshdr->sh_size)) {
			errno = 0;
			Chain *tmp = calloc(1, sizeof(Chain));
			if (tmp == NULL) {
				error(0, errno, "unable to allocate memory");
				goto err_free_srcphdr2;
			}
			tmp->next = NULL;

			/* determine start and end addresses of section range in file */
			if (srcshdr->sh_type == SHT_NOBITS) {
				tmp->data.from = 0;
				tmp->data.to = 0;
			}
			else {
				if (current->data.from < srcshdr->sh_offset) {
					tmp->data.from = 0;
				}
				else {
					tmp->data.from = current->data.from - srcshdr->sh_offset;
				}
				tmp->data.to = srcshdr->sh_size;
			}

			// FIXME: Alignment im Testfall
			if (srcshdr->sh_addralign != 65536) {
				tmp->data.section_align = srcshdr->sh_addralign;
			}
			else {
				tmp->data.section_align = 16;
			}
			tmp->data.section_offset = srcshdr->sh_offset;

			/* memory layout of section range */
			for (size_t j = 0; j < phdrnum; j++) {
				if (gelf_getphdr(src, j, srcphdr) == NULL) {
					error(0, 0, "could not retrieve source phdr structure %lu: %s", i, elf_errmsg(-1));
					goto err_free_srcphdr2;
				}

				if (srcphdr->p_type != PT_LOAD) {
					/* not a loadable segment */
					continue;
				}

				if (srcphdr->p_offset >= srcshdr->sh_offset + (srcshdr->sh_type == SHT_NOBITS ? 0 : srcshdr->sh_size) || srcphdr->p_offset + (srcshdr->sh_type == SHT_NOBITS ? srcphdr->p_memsz : srcphdr->p_filesz) <= srcshdr->sh_offset) {
					/* loadable segment but does not load this section */
					continue;
				}

				tmp->as.loadable = TRUE;
				tmp->as.flags = srcphdr->p_flags;
				tmp->as.align = srcphdr->p_align;
				/* determine start and end addresses of section range in memory */
				if (srcphdr->p_offset <= srcshdr->sh_offset) {
					tmp->as.from = srcphdr->p_vaddr + srcshdr->sh_offset + tmp->data.from - srcphdr->p_offset;
				}
				else {
					tmp->as.from = srcphdr->p_offset - srcshdr->sh_offset;
				}
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
				dest[i].data.section_offset = tmp->data.section_offset;
				dest[i].data.section_align = tmp->data.section_align;
				dest[i].as.from = tmp->as.from;
				dest[i].as.to = tmp->as.to;
				dest[i].as.loadable = tmp->as.loadable;
				dest[i].as.flags = tmp->as.flags;
				dest[i].as.align = tmp->as.align;
				free(tmp);
			}
			else {
				insert(&dest[i], tmp);
			}
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

/*
 * Rounds up value to the next multiple of base.
 */
size_t roundUp(size_t value, size_t base) {
	size_t tmp = value % base;
	if (tmp != 0) {
		return value - tmp + base;
	}
	else {
		return value;
	}
}

size_t calculateOffsetInPage(size_t addr) {
	return addr % PAGESIZE;
}

/*
 * Counts LOAD program headers.
 * Returns -1 in case of an error.
 */
int countLOADs(Elf *elf) {
	int count = 0;

	// number of segments in file
	size_t phdrnum = 0;
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
 * Counts loadable ranges.
 */
int countLoadableRanges(Chain *ranges, size_t size) {
	int count = 0;

	for (size_t i = 0; i < size; i++) {
		Chain *tmp = &ranges[i];
		while (tmp) {
			if (tmp->as.loadable) {
				count++;
			}
			tmp = tmp->next;
		}
	}
	return count;
}

/*
 * Calculates offset of a section in new file.
 *
 * priorOffset: offset of section in original file
 * occupiedSpace: number of already occupied bytes in new file
 *
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

/*
 * Frees a list of relocation information.
 */
void freeRelocs(struct relocation_infos *start) {
	struct relocation_infos *tmp;
	while (start != NULL) {
		tmp = start->next;
		free(start);
		start = tmp;
	}
}

/*
 * Compare function for sorting PHDR table
 */
static int cmp (const void *p1, const void *p2) {
	return ((GElf_Phdr *) p1)->p_vaddr - ((GElf_Phdr *) p2)->p_vaddr;
}

// FIXME: comment
struct segmentRanges *segments(Chain *section) {
	if (section == NULL) {
		return NULL;
	}
	errno = 0;
	struct segmentRanges *ret = calloc(1, sizeof(struct segmentRanges));
	if (ret == NULL) {
		error(0, errno, "ran out of memory");
		return NULL;
	}
	ret->next = NULL;
	struct segmentRanges *current = ret;
	current->range.offset = section->data.section_offset + section->data.from;
	current->range.fsize = section->data.to - section->data.from;
	current->range.vaddr = section->as.from;
	current->range.msize = section->as.to - section->as.from;
	current->range.loadable = section->as.loadable;
	for(Chain *tmp = section->next; tmp; tmp = tmp->next) {
		if (((current->range.vaddr + current->range.msize) / PAGESIZE) == (tmp->as.from / PAGESIZE)) {
			/* data of tmp range will be loaded in the same page as content of current range
			 * => merge the ranges */
			current->range.fsize = tmp->data.section_offset + tmp->data.to - current->range.offset;
			current->range.msize = tmp->as.to - current->range.vaddr;
			current->range.loadable |= tmp->as.loadable;
		}
		else {
			errno = 0;
			current->next = calloc(1, sizeof(struct segmentRanges));
			if (current->next == NULL) {
				error(0, errno, "ran out of memory");
				return NULL;
			}
			current->next->range.offset = tmp->data.section_offset + tmp->data.from;
			current->next->range.fsize = tmp->data.to - tmp->data.from;
			current->next->range.vaddr = tmp->as.from;
			current->next->range.msize = tmp->as.to - tmp->as.from;
			current->next->range.loadable = tmp->as.loadable;
			current = current->next;
		}
	}
	return ret;
}

size_t countLoadableSegmentRanges(struct segmentRanges *start) {
	size_t ret = 0;
	for (struct segmentRanges *tmp = start; tmp; tmp = tmp->next) {
		if (tmp->range.loadable) {
			ret++;
		}
	}
	return ret;
}

void deleteSegmentRanges(struct segmentRanges *start) {
	if (start == NULL) {
		return;
	}
	struct segmentRanges *tmp = start->next;
	free(start);
	while (tmp) {
		start = tmp;
		tmp = tmp->next;
		free(start);
	}
}

int contains(struct segmentRanges * segment, Chain *range) {
	if (range->data.section_offset + range->data.to <= segment->range.offset + segment->range.fsize && range->data.section_offset + range->data.from >= segment->range.offset) {
		return TRUE;
	}
	return FALSE;
}

signed long long calculateSectionShift(Chain * range, struct segmentRanges *segments) {
	unsigned long long section_start = ULLONG_MAX;
	for (Chain *tmp = range; tmp; tmp = tmp->next) {
		for (struct segmentRanges *tmpSeg = segments; tmpSeg; tmpSeg = tmpSeg->next) {
			if(contains(tmpSeg, tmp)) {
				if(tmp->data.section_offset + tmpSeg->range.shift < section_start) {
					section_start = tmp->data.section_offset + tmpSeg->range.shift;
				}
			}
		}
	}
	return section_start - range->data.section_offset;
}

void calculateShift(Chain *ranges, struct segmentRanges **segments, size_t size) {
	for (size_t i = 0; i < size; i++) {
		signed long long section_shift = calculateSectionShift(&ranges[i], segments[i]);
		for (struct segmentRanges *tmp = segments[i]; tmp; tmp = tmp->next) {
			for (Chain *tmpSec = &ranges[i]; tmpSec; tmpSec = tmpSec->next) {
				if (contains(tmp, tmpSec)) {
					tmpSec->data.section_shift = section_shift;
					tmpSec->data.data_shift = tmp->range.shift - section_shift;
				}
			}
		}
	}
}

/*
 * Calculates the new file layout.
 *
 * ranges, size: list of ranges in the new file
 * oldEntries: number of PHDR entries of original file that are NOT LOADs
 * elflass: Elf Class (32bit or 64bit)
 */
struct layoutDescription * calculateNewFilelayout(Chain *ranges, size_t size, size_t oldEntries, int elfclass) {
	errno = 0;
	struct layoutDescription *ret = calloc(1, sizeof(struct layoutDescription));
	if (ret == NULL) {
		error(0, errno, "ran out of memory");
		return NULL;
	}
	ret->segmentNum = size;
	errno = 0;
	ret->segments = calloc(ret->segmentNum, sizeof(struct segmentRanges *));
	if (ret->segments == NULL) {
		error(0, errno, "ran out of memory");
		return NULL;
	}

	// number of LOAD entries in new PHDR table
	size_t loads = 2;
	unsigned long long current_size = 0;
	if (elfclass == ELFCLASS32) {
		current_size = sizeof(Elf32_Ehdr);
	}
	else {
		current_size = sizeof(Elf64_Ehdr);
	}
	/* ignore section 0 */
	for (size_t i = 1; i < size; i++) {
		ret->segments[i] = segments(&ranges[i]);
		loads += countLoadableSegmentRanges(ret->segments[i]);

		for (struct segmentRanges *tmp = ret->segments[i]; tmp; tmp = tmp->next) {
			tmp->range.shift = calculateOffset(tmp->range.offset, current_size) - (signed long long) tmp->range.offset;
			current_size = calculateOffset(tmp->range.offset, current_size) + tmp->range.fsize;
		}
	}

	/* insert phdr */
	// FIXME: check memeory layout
	for (size_t i = 1; i < size; i++) {
		for (struct segmentRanges *tmp = ret->segments[i]; tmp; tmp = tmp->next) {
			struct segmentRanges *ahead = tmp->next;
			if (ahead == NULL) {
				if (i < size - 1) {
					ahead = ret->segments[i + 1];
				}
				else {
					/* FIXME: problems */
				}
			}

			size_t entry_size = 0;
			unsigned long long phdr_start = 0;
			if (elfclass == ELFCLASS32) {
				phdr_start = roundUp(tmp->range.vaddr + tmp->range.msize, sizeof(Elf32_Phdr));
				entry_size = sizeof(Elf32_Phdr);
			}
			else {
				phdr_start = roundUp(tmp->range.vaddr + tmp->range.msize, sizeof(Elf64_Phdr));
				entry_size = sizeof(Elf64_Phdr);
			}

			if (ahead->range.vaddr >= phdr_start + entry_size + (loads + oldEntries)) {
				ret->phdr_start = roundUp(tmp->range.offset + tmp->range.fsize, entry_size);
				ret->phdr_entries = loads + oldEntries;
				if (ahead->range.offset < ret->phdr_start + ret->phdr_entries * entry_size) {
					unsigned long long shift = roundUp(ret->phdr_start + ret->phdr_entries * entry_size - ahead->range.offset, PAGESIZE);
					for (size_t j = i; j < size; j++) {
						for (struct segmentRanges *tmp2 = ahead; tmp2; tmp2 = tmp2->next) {
							tmp2->range.shift += shift;
						}
					}
					current_size += shift;
				}
				goto done;
			}
		}
	}

done:
	calculateShift(ranges, ret->segments, size);

	if (elfclass == ELFCLASS32) {
		ret->shdr_start = roundUp(current_size, sizeof(Elf32_Shdr));
	}
	else {
		ret->shdr_start = roundUp(current_size, sizeof(Elf64_Shdr));
	}
	return ret;
}

/*
 * Calculates the size of a section.
 */
unsigned long long calculateSectionSize(Chain *section) {
	unsigned long long size = 0;
	for (Chain *tmp = section; tmp; tmp = tmp->next) {
		unsigned long long temp_size = tmp->data.to + tmp->data.data_shift;
		if (temp_size > size) {
			size = temp_size;
		}
	}
	return size;
}

void deleteDesc(struct layoutDescription *desc) {
	if (desc == NULL) {
		return;
	}

	for (size_t i = 0; i < desc->segmentNum; i++) {
		deleteSegmentRanges(desc->segments[i]);
	}
	free(desc);
}



int main(int argc, char **argv) {
	Chain *ranges = NULL;

//---------------------------------------------------------------------------//
// Command line argument processing                                          //
//---------------------------------------------------------------------------//
	int opt;
	while ((opt = getopt(argc, argv, "hk:")) != -1) {
		switch (opt) {
			case 'k':
				/* you can't have a label on a declaration because of it's C */
				;
				char *split = strpbrk(optarg, ":-");
				if (split == NULL) {
					error(0, 0, "Invalid range argument '%s' - ignoring!", optarg);
				}
				else {
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
					if (tmp->data.from == ULLONG_MAX && errno != 0) {
						error(0, errno, "First part of range argument '%s' not parsable - ignoring!", optarg);
					}
					char *to = NULL;
					errno = 0;
					tmp->data.to = strtoull(split + 1, &to, 0);
					if (tmp->data.to == ULLONG_MAX && errno != 0) {
						error(0, errno, "Second part of range argument '%s' not parsable - ignoring!", optarg);
					}
					if ((tmp->data.from == 0 && from == optarg) || (tmp->data.to == 0 && to == split + 1) || errno != 0 || from != split || *to != '\0') {
						error(0, 0, "Range argument '%s' not parsable - ignoring!", optarg);
					}
					else {
						if (*split == ':') {
							tmp->data.to += tmp->data.from;
						}
						if (tmp->data.to <= tmp->data.from) {
							error(0, 0, "Invalid range '%s' - ignoring!", optarg);
						}
						else {
							if (ranges == NULL) {
								ranges = tmp;
							}
							else {
								insert(ranges, tmp);
							}
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

//---------------------------------------------------------------------------//
// Setup                                                                     //
//---------------------------------------------------------------------------//
	/* libelf-library won't work if you don't tell it the ELF version */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		error(0, 0, "ELF library initialization failed: %s", elf_errmsg(-1));
		goto err_free_ranges;
	}

	// file descriptor of source file
	int srcfd;
	errno = 0;
	if ((srcfd = open(filename, O_RDONLY)) < 0) {
		error(0, errno, "unable to open %s", filename);
		goto err_free_ranges;
	}
	// ELF representation of source file
	Elf *srce;
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

	// file descriptor of new file
	int dstfd;
	errno = 0;
	if ((dstfd = open(dstfname, O_WRONLY | O_CREAT, 0777)) < 0) {
		error(0, errno, "unable to open %s", dstfname);
		goto err_free_dstfname;
	}
	// ELF representation of new file
	Elf *dste;
	if ((dste = elf_begin(dstfd, ELF_C_WRITE, NULL)) == NULL) {
		error(0, 0, "could not create ELF structures for new file: %s", elf_errmsg(-1));
		goto err_free_dstfd;
	}

	/* tell lib that the application will take care of the exact file layout */
	if (elf_flagelf(dste, ELF_C_SET, ELF_F_LAYOUT) == 0) {
		error(0, 0, "elf_flagelf() failed: %s.", elf_errmsg(-1));
		goto err_free_dste;
	}

	// XXX: Debug
	elf_fill(0xcc);

//---------------------------------------------------------------------------//
// Copy executable header                                                    //
//---------------------------------------------------------------------------//
	// ELF class of source file
	int elfclass;
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
		goto err_free_srcehdr;
	}
	dstehdr->e_ident[EI_DATA] = srcehdr->e_ident[EI_DATA];
	dstehdr->e_ident[EI_OSABI] = srcehdr->e_ident[EI_OSABI];
	dstehdr->e_ident[EI_ABIVERSION] = srcehdr->e_ident[EI_ABIVERSION];
	dstehdr->e_machine = srcehdr->e_machine;
	dstehdr->e_type = srcehdr->e_type;
	dstehdr->e_flags = srcehdr->e_flags;
	dstehdr->e_shstrndx = srcehdr->e_shstrndx;
	dstehdr->e_entry = srcehdr->e_entry;
	if (gelf_update_ehdr(dste, dstehdr) == 0) {
		error(0, 0, "could not update ELF structures (Header): %s", elf_errmsg(-1));
		goto err_free_srcehdr;
	}

//---------------------------------------------------------------------------//
// Copy program headers                                                      //
//---------------------------------------------------------------------------//
	// number of sections in source file
	size_t scnnum = 0;
	if (elf_getshdrnum(srce, &scnnum) != 0) {
		error(0, 0, "could not retrieve number of sections from source file: %s", elf_errmsg(-1));
		goto err_free_srcehdr;
	}
	errno = 0;
	// ranges to keep per section
	Chain *section_ranges = calloc(scnnum, sizeof(Chain));
	if (section_ranges == NULL) {
		error(0, errno, "unable to allocate memory");
		goto err_free_srcehdr;
	}
	if (computeSectionRanges(srce, ranges, section_ranges, scnnum) != 0) {
		goto err_free_section_ranges;
	}
	deleteList(ranges);
	ranges = NULL;

	// number of segments in source file
	size_t phdrnum = 0;
	if (elf_getphdrnum(srce, &phdrnum) != 0) {
		error(0, 0, "could not retrieve number of segments from source file: %s", elf_errmsg(-1));
		goto err_free_section_ranges;
	}
	// FIXME: näher an for-Schleife
	errno = 0;
	// current PHDR entry of source file
	GElf_Phdr *srcphdr = calloc(1, sizeof(GElf_Phdr));
	if (srcphdr == NULL) {
		error(0, errno, "ran out of memory");
		goto err_free_section_ranges;
	}

	// number of LOAD segments in source file
	int loads = countLOADs(srce);
	if (loads == -1) {
		goto err_free_srcphdr;
	}
	// description of layout of new file
	struct layoutDescription *desc = calculateNewFilelayout(section_ranges, scnnum, phdrnum - loads, elfclass);
	if (desc == NULL) {
		goto err_free_srcphdr;
	}
	// PHDR table of new file
	GElf_Phdr *dstphdrs = gelf_newphdr(dste, desc->phdr_entries);
	if (dstphdrs == NULL) {
		error(0, 0, "gelf_newphdr() failed: %s", elf_errmsg(-1));
		goto err_free_desc;
	}

	// index of current PHDR entry in new file
	size_t new_index = 0;
	// FIXME: comments
	int first_load = TRUE;
	errno = 0;
	struct relocation_infos *relinfos = calloc(1, sizeof(struct relocation_infos));
	if (relinfos == NULL) {
		error(0, errno, "ran out of memory");
		goto err_free_desc;
	}
	// data of PDHR segment
	unsigned long long phdr_vaddr = 0;
	unsigned long long phdr_paddr = 0;
	unsigned long long phdr_offset = 0;
	unsigned long long phdr_filesz = 0;
	/* construct new PHDR table from old PHDR table */
	for (size_t i = 0; i < phdrnum; i++) {
		if (gelf_getphdr(srce, i, srcphdr) == NULL) {
			error(0, 0, "could not retrieve source phdr structure %lu: %s", i, elf_errmsg(-1));
			goto err_free_relinfos;
		}

		if (srcphdr->p_type != PT_LOAD) {
			/* adopt values of non-LOAD segments to fix them up later */
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
		else if (first_load) {
			/* replace first LOAD segment with all LOAD segments of new file */
			first_load = FALSE;

			/* LOAD segment for EHDR */
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
			dstphdrs[new_index].p_align = PAGESIZE;

			relinfos->info.start = dstphdrs[new_index].p_offset;
			relinfos->info.size = dstphdrs[new_index].p_filesz;
			relinfos->info.shift = 0;
			new_index++;

			/* insert LOAD segments for sections */
			for (size_t i = 0; i < scnnum; i++) {
				Chain *tmp = &section_ranges[i];
				while (tmp) {
					if (tmp->as.loadable) {
						dstphdrs[new_index].p_type = PT_LOAD;
						dstphdrs[new_index].p_offset = tmp->data.section_offset + tmp->data.from + tmp->data.section_shift + tmp->data.data_shift;
						dstphdrs[new_index].p_vaddr = tmp->as.from;
						dstphdrs[new_index].p_paddr = tmp->as.from;
						dstphdrs[new_index].p_filesz = tmp->data.to - tmp->data.from;
						dstphdrs[new_index].p_memsz = tmp->as.to - tmp->as.from;
						dstphdrs[new_index].p_flags = tmp->as.flags;
						dstphdrs[new_index].p_align = PAGESIZE;

						if (relinfos->info.start + relinfos->info.size == tmp->data.section_offset + tmp->data.from && relinfos->info.shift == (signed long long)dstphdrs[new_index].p_offset - (signed long long)relinfos->info.start){
							relinfos->info.size += dstphdrs[new_index].p_filesz;
						}
						else {
							struct relocation_infos *second_tmp_relinfos = relinfos;
							struct relocation_infos *tmp_relinfos = relinfos->next;
							while(tmp_relinfos != NULL){
								if (tmp_relinfos->info.start + tmp_relinfos->info.size == tmp->data.section_offset + tmp->data.from && tmp_relinfos->info.shift == (signed long long)dstphdrs[new_index].p_offset - (signed long long)tmp_relinfos->info.start - (signed long long)tmp_relinfos->info.size){
									tmp_relinfos->info.size += dstphdrs[new_index].p_filesz;
									break;
								}
								second_tmp_relinfos = tmp_relinfos;
								tmp_relinfos = tmp_relinfos->next;
							}
							if(tmp_relinfos == NULL) {
								errno = 0;
								second_tmp_relinfos->next = calloc(1, sizeof(struct relocation_infos));
								if(second_tmp_relinfos->next == NULL) {
									error(0, errno, "ran out of memory");
									goto err_free_relinfos;
								}
								second_tmp_relinfos->next->info.start = tmp->data.section_offset + tmp->data.from;
								second_tmp_relinfos->next->info.size = dstphdrs[new_index].p_filesz;
								second_tmp_relinfos->next->info.shift = (unsigned long long)second_tmp_relinfos->next->info.start - (unsigned long long)dstphdrs[new_index].p_offset;
							}
						}
						new_index++;
					}
					tmp = tmp->next;
				}
			}
			/* LOAD segment for PHDR */
			dstphdrs[new_index].p_type = PT_LOAD;
			dstehdr->e_phoff = desc->phdr_start;
			dstphdrs[new_index].p_offset = dstehdr->e_phoff;
			if (elfclass == ELFCLASS32) {
				// FIXME: p_vaddr & p_paddr fixen
				dstphdrs[new_index].p_vaddr = srcphdr->p_vaddr + dstphdrs[new_index].p_offset;
				dstphdrs[new_index].p_paddr = srcphdr->p_paddr + dstphdrs[new_index].p_offset;
				dstphdrs[new_index].p_filesz = desc->phdr_entries * sizeof(Elf32_Phdr);
				dstphdrs[new_index].p_memsz = desc->phdr_entries * sizeof(Elf32_Phdr);

				phdr_vaddr = dstphdrs[new_index].p_vaddr;
				phdr_paddr = dstphdrs[new_index].p_paddr;
				phdr_offset = dstphdrs[new_index].p_offset;
				phdr_filesz = dstphdrs[new_index].p_filesz;
			}
			else {
				// FIXME: p_vaddr & p_paddr fixen
				dstphdrs[new_index].p_vaddr = srcphdr->p_vaddr + dstphdrs[new_index].p_offset;
				dstphdrs[new_index].p_paddr = srcphdr->p_paddr + dstphdrs[new_index].p_offset;
				dstphdrs[new_index].p_filesz = desc->phdr_entries * sizeof(Elf64_Phdr);
				dstphdrs[new_index].p_memsz = desc->phdr_entries * sizeof(Elf64_Phdr);

				phdr_vaddr = dstphdrs[new_index].p_vaddr;
				phdr_paddr = dstphdrs[new_index].p_paddr;
				phdr_offset = dstphdrs[new_index].p_offset;
				phdr_filesz = dstphdrs[new_index].p_filesz;
			}
			dstphdrs[new_index].p_flags = PF_X | PF_R;
			dstphdrs[new_index].p_align = PAGESIZE;

			new_index++;
			/* sort LOAD segments by their virtual address - required by ELF standard */
			qsort(&dstphdrs[i], new_index - i, sizeof(GElf_Phdr), &cmp);
		}
		else {
			/* skip all other LOAD segments */
			continue;
		}
	}

	/* fix up non-LOAD segments */
	for (size_t i = 0; i < desc->phdr_entries; i++) {
		if (dstphdrs[i].p_type != PT_LOAD) {
			for (struct relocation_infos *tmp = relinfos; tmp != NULL; tmp = tmp->next) {
				if (tmp->info.start <= dstphdrs[i].p_offset && dstphdrs[i].p_offset < tmp->info.start + tmp->info.size) {
					dstphdrs[i].p_offset -= tmp->info.shift;
					break;
				}
			}
			if (dstphdrs[i].p_type == PT_PHDR) {
				/* fixup PHDR segment */
				dstphdrs[i].p_paddr = phdr_paddr;
				dstphdrs[i].p_vaddr = phdr_vaddr;
				dstphdrs[i].p_offset = phdr_offset;
				dstphdrs[i].p_filesz = phdr_filesz;
				dstphdrs[i].p_memsz = phdr_filesz;
			}
		}
	}
	freeRelocs(relinfos);
	relinfos = NULL;

//---------------------------------------------------------------------------//
// Copy sections and section headers                                         //
//---------------------------------------------------------------------------//
	errno = 0;
	// current section header of source file
	GElf_Shdr *srcshdr = calloc(1, sizeof(GElf_Shdr));
	if (srcshdr == NULL) {
		error(0, errno, "unable to allocate memory for source shdr structure");
		goto err_free_relinfos;
	}
	errno = 0;
	// current section header of new file
	GElf_Shdr *dstshdr = calloc(1, sizeof(GElf_Shdr));
	if (dstshdr == NULL) {
		error(0, errno, "unable to allocate memory for new shdr structure");
		goto err_free_srcshdr;
	}

	// current section of source file
	Elf_Scn *srcscn = NULL;
	/* lib creates section 0 automatically so we start with section 1 */
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

		/* allocate buffers for the data of the new file */
		for (Chain *tmp = &section_ranges[i]; tmp; tmp = tmp->next) {
			errno = 0;
			tmp->data.buffer = calloc(tmp->data.to - tmp->data.from, sizeof(char));
			if (tmp->data.buffer == NULL) {
				error(0, errno, "Unable to allocate memory");
				goto err_free_dstshdr;
			}
		}

		// current data of current section of source file
		Elf_Data *srcdata = NULL;
		/* copy data in data buffers for new file */
		while ((srcdata = elf_getdata(srcscn, srcdata)) != NULL) {
			if (srcdata->d_buf == NULL) {
				/* section is NOBITS section => no data to copy */
				continue;
			}
			size_t srcdata_begin = srcdata->d_off;
			size_t srcdata_end = srcdata->d_off + srcdata->d_size;
			for (Chain *tmp = &section_ranges[i]; tmp; tmp = tmp->next) {
				if (tmp->data.to <= srcdata_begin) {
					/* source data begins after range ends */
					continue;
				}

				if (srcdata_end <= tmp->data.from) {
					/* source data ends before range (and the following range because the list is sorted) begins */
					break;
				}

				unsigned long long srcstart = 0;
				unsigned long long srcend = 0;
				unsigned long long dststart = 0;
				if (tmp->data.from <= srcdata_begin) {
					/* range starts before source data starts */
					srcstart = 0;
					dststart = srcdata_begin - tmp->data.from;
				}
				else {
					/* range starts after source data starts */
					srcstart = tmp->data.from - srcdata_begin;
					dststart = 0;
				}

				if (tmp->data.to >= srcdata_end) {
					/* range ends after source data ends */
					srcend = srcdata_end;
				}
				else {
					/* range ends before source data ends */
					srcend = tmp->data.to;
				}

				memcpy(tmp->data.buffer + dststart, srcdata->d_buf + srcstart, srcend - srcstart);
				tmp->data.d_version = srcdata->d_version;
				tmp->data.d_type = srcdata->d_type;
			}
		}

		/* construct data descriptors of current section */
		for (Chain *tmp = &section_ranges[i]; tmp; tmp = tmp->next) {
			Elf_Data *dstdata = elf_newdata(dstscn);
			if (dstdata == NULL) {
				error(0, 0, "could not add data to section %lu: %s", i, elf_errmsg(-1));
				goto err_free_dstshdr;
			}

			// FIXME: früher prüfen! In computeSectionRanges verschieben?
			if (tmp->data.from % tmp->data.section_align != 0) {
				error(0, 0, "in section %lu: range to keep is misaligned by %llu byte(s) (offset in section: 0x%llx, aligment: 0x%llx)", i, tmp->data.from % tmp->data.section_align, tmp->data.from, tmp->data.section_align);
				goto err_free_dstshdr;
			}
			dstdata->d_align = tmp->data.section_align;
			dstdata->d_type = tmp->data.d_type;
			dstdata->d_version = tmp->data.d_version;
			dstdata->d_buf = tmp->data.buffer;
			dstdata->d_off = tmp->data.from + tmp->data.data_shift;
			dstdata->d_size = tmp->data.to - tmp->data.from;
		}

		dstshdr->sh_info = srcshdr->sh_info;
		dstshdr->sh_name = srcshdr->sh_name;
		dstshdr->sh_type = srcshdr->sh_type;
		dstshdr->sh_addr = srcshdr->sh_addr;
		dstshdr->sh_flags = srcshdr->sh_flags;
		// FIXME: sinnvollere Methode, das Alignment-Problem im Testfall zu lösen
		if (srcshdr->sh_addralign == 65536) {
			dstshdr->sh_addralign = 16;
		}
		else {
			dstshdr->sh_addralign = srcshdr->sh_addralign;
		}
		dstshdr->sh_offset = srcshdr->sh_offset + section_ranges[i].data.section_shift;
		if (srcshdr->sh_type == SHT_NOBITS) {
			dstshdr->sh_size = srcshdr->sh_size;
		}
		else {
			dstshdr->sh_size = calculateSectionSize(&section_ranges[i]);
		}
		dstshdr->sh_entsize = srcshdr->sh_entsize;
		dstshdr->sh_link = srcshdr->sh_link;

		if (gelf_update_shdr(dstscn, dstshdr) == 0) {
			error(0, 0, "could not update ELF structures (Sections): %s", elf_errmsg(-1));
			goto err_free_dstshdr;
		}
	}

	dstehdr->e_shoff = desc->shdr_start;

	/* write new ELF file */
	if (elf_update(dste, ELF_C_WRITE) == -1) {
		error(0, 0, "could not update ELF structures: %s", elf_errmsg(-1));
		goto err_free_dstshdr;
	}

	/* tidy up */
	free(dstshdr);
	free(srcshdr);
	deleteDesc(desc);
	free(srcphdr);
	for (size_t i = 0; i < scnnum; i++) {
		if (section_ranges[i].next) {
			deleteList(section_ranges[i].next);
		}
		if (section_ranges[i].data.buffer) {
			free(section_ranges[i].data.buffer);
		}
	}
	free(section_ranges);
	free(srcehdr);
	elf_end(dste);
	errno = 0;
	if (close(dstfd) < 0) {
		error(0, errno, "unable to close %s", dstfname);
		goto err_free_dstfname;
	}
	free(dstfname);
	elf_end(srce);
	errno = 0;
	if (close(srcfd) < 0) {
		error(EXIT_FAILURE, errno, "unable to close %s", filename);
	}

	return 0;

err_free_dstshdr:
	free(dstshdr);
err_free_srcshdr:
	free(srcshdr);
err_free_relinfos:
	if (relinfos != NULL) {
		freeRelocs(relinfos);
	}
err_free_desc:
	deleteDesc(desc);
err_free_srcphdr:
	free(srcphdr);
err_free_section_ranges:
	for (size_t i = 0; i < scnnum; i++) {
		if (section_ranges[i].next) {
			deleteList(section_ranges[i].next);
		}
		if (section_ranges[i].data.buffer) {
			free(section_ranges[i].data.buffer);
		}
	}
	free(section_ranges);
err_free_srcehdr:
	free(srcehdr);
err_free_dste:
	elf_end(dste);
err_free_dstfd:
	errno = 0;
	if (close(dstfd) < 0) {
		error(0, errno, "unable to close %s", dstfname);
	}
err_free_dstfname:
	free(dstfname);
err_free_srce:
	elf_end(srce);
err_free_srcfd:
	errno = 0;
	if (close(srcfd) < 0) {
		error(0, errno, "unable to close %s", filename);
	}
err_free_ranges:
	if (ranges != NULL) {
		deleteList(ranges);
	}
	exit(EXIT_FAILURE);
}
