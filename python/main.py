/** \brief Page size to align segment ranges */
#define PAGESIZE 0x1000
#define FALSE 0x00
#define TRUE 0xff
/** \brief Alignment for PHDR table in file (32bit version) */
#define PHDR32ALIGN 8
/** \brief Alignment for PHDR table in file (64bit version) */
#define PHDR64ALIGN 8
/** \brief Alignment for SHDR table in file (32bit version) */
#define SHDR32ALIGN 8
/** \brief Alignment for SHDR table in file (64bit version) */
#define SHDR64ALIGN 8

/**
 * \brief Data range to keep
 *
 * A range of data that the user wants to keep. Addresses are relativ to the
 * start address of the containing section and based on the file
 * representation.
 */
typedef struct range{
	/** \brief Start address of the data range relativ to its containing
	 *         section */
	unsigned long long from;
	/** \brief End address (exclusive) of the data range relativ to its
	 *         containing section */
	unsigned long long to;
	/** \brief Offset of the containing section in the file */
	unsigned long long section_offset;
	/** \brief Alignment requirement of the containing section */
	unsigned long long section_align;
	/** \brief Shift of the containing section in the file. Negative values
	 *         mean a shift towards the beginning of the file */
	signed long long section_shift;
	/** \brief Shift of the data range in its section. Negative values mean a
	 *         shift towards the beginning of the section */
	signed long long data_shift;
	/** \brief Buffer for the data described by this struct */
	char *buffer;
	/** \brief Values of corresponding members of Elf_Data library struct */
	Elf_Type d_type;
	/** \brief Values of corresponding members of Elf_Data library struct */
	unsigned int d_version;
} Range;

/**
 * \brief Information about memory layout of the corresponding data range
 */
struct address_space_info{
	/** \brief Flag if the range is part of a LOAD segment */
	int loadable;
	/** \brief Flags of the containing segment */
	unsigned long long flags;
	/** \brief Alignment requirement of the containing segment */
	unsigned long long align;
	/** \brief Start address of the data range in memory */
	unsigned long long from;
	/** \brief End address (exclusive) of the data range in memory */
	unsigned long long to;
};

/**
 * \brief List of [data ranges](@ref range) and associated [address space description]
 *        (@ref address_space_info)
 */
typedef struct chain{
	Range data;
	struct chain *next;
	struct address_space_info as;
} Chain;

/**
 * \brief Address range that can be permutated
 *
 * Range of addresses that can be rearranged to save space. Rearranged means
 * that ordering of ranges in the input file may not be preserved. The address
 * range can span over multiple [data ranges](@ref range) and the room between
 * them.  A side effect of this is that there need not be data behind every
 * address in this address range.
 *
 * Address ranges are constructed in such a way that [data ranges](@ref range)
 * which are loaded in the same page reside in the same address range.
 */
struct segmentRange {
	/** \brief Offset of the range in the input file */
	unsigned long long offset;
	/** \brief Size of the range in the file */
	unsigned long long fsize;
	/** \brief Start address of the range in memory */
	unsigned long long vaddr;
	/** \brief Size of the range in memory */
	unsigned long long msize;
	/** \brief Flags of the containing LOAD segment */
	unsigned long long flags;
	/** \brief Shift of the range in the new file. Negative values mean a
	 *          shift towards the beginning of the file */
	signed long long shift;
	/** \brief  Flag if the range is part of a LOAD segment */
	int loadable;
	/** \brief Offset of the containing section in the new file */
	unsigned long long section_start;
};

/**
 * \brief Description of the new file layout
 */
struct layoutDescription {
	/** \brief Offset of PHDR table in new file */
	unsigned long long phdr_start;
	/** \brief Offset of PHDR table in memory after shrinking the original ELF
	 *         file*/
	unsigned long long phdr_vaddr;
	/** \brief Number of entries in new PHDR table */
	unsigned long long phdr_entries;
	/** \brief Offset of SHDR table in new file*/
	unsigned long long shdr_start;
	struct segmentRanges** segments;
	size_t segmentNum;
	struct segmentRanges *segmentList;
	unsigned long long listEntries;
};

/**
 * \brief Permutation of [segment ranges](@ref segmentRange)
 */
struct permutation {
	/** \brief Array of indexes, describing the current permutation */
	unsigned long long *tmp;
	/** \brief Array of indexes, describing the current optimum */
	unsigned long long *result;
	/** \brief Size of the arrays */
	unsigned long long numEntries;
	/** \brief Size of the segment ranges in ordering of the current optimum */
	unsigned long long size;
};


/**
 * \brief Compare function for sorting PHDR table
 *
 * The ELF standard says that LOAD program headers are sorted by their virtual
 * addresses in ascending order. This function is used as compare function for
 * `qsort`.
 *
 * \param p1, p2 The program header to compare
 *
 * \return An integer indicating if `p1` is smaller, equal or bigger than `p2`
 */
static int cmp (const void *p1, const void *p2) {
	return ((GElf_Phdr *) p1)->p_vaddr - ((GElf_Phdr *) p2)->p_vaddr;
}

/**
 * \brief Destructor for a list of [segment ranges](@ref segmentRange)
 *
 * \param start The list to free
 */
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

/**
 * \brief Destructor for ::layoutDescription
 *
 * \param desc The layout description to free
 */
void deleteDesc(struct layoutDescription *desc) {
	if (desc == NULL) {
		return;
	}

	for (size_t i = 0; i < desc->segmentNum; i++) {
		deleteSegmentRanges(desc->segments[i]);
	}
	deleteSegmentRanges(desc->segmentList);
	free(desc->segments);
	free(desc);
}

/**
 * \brief Calculates the size of a section
 *
 * \param section List of data ranges in a section
 *
 * \return The size of the section
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



int main(int argc, char **argv) {
###########################################
### TODO ##################################
###########################################
	/* construct new PHDR table from old PHDR table */
	for (size_t i = 0; i < phdrnum; i++) {
		if (gelf_getphdr(srce, i, srcphdr) == NULL) {
			error(0, 0, "Could not retrieve phdr structure %lu of input file: %s", i, elf_errmsg(-1));
			goto err_free_desc;
		}

		if (srcphdr->p_type != PT_LOAD) {
			/* copy values of non-LOAD segments - addresses and offsets will be
			 * fixed later */
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
			/* replace first LOAD segment of input file with all LOAD segments
			 * of output file */
			first_load = FALSE;

			for (struct segmentRanges *tmp = desc->segmentList; tmp; tmp = tmp->next) {
				if (tmp->range.loadable) {
					dstphdrs[new_index].p_type = PT_LOAD;
					dstphdrs[new_index].p_offset = tmp->range.offset + tmp->range.shift;
					dstphdrs[new_index].p_vaddr = tmp->range.vaddr;
					dstphdrs[new_index].p_paddr = tmp->range.vaddr;
					dstphdrs[new_index].p_filesz = tmp->range.fsize;
					dstphdrs[new_index].p_memsz = tmp->range.msize;
					dstphdrs[new_index].p_flags = tmp->range.flags;
					dstphdrs[new_index].p_align = PAGESIZE;
					new_index++;
				}
			}
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
			for (struct segmentRanges *tmp = desc->segmentList; tmp; tmp = tmp->next) {
				if (tmp->range.vaddr <= dstphdrs[i].p_vaddr && dstphdrs[i].p_vaddr + dstphdrs[i].p_filesz <= tmp->range.vaddr + tmp->range.fsize) {
					dstphdrs[i].p_offset = tmp->range.offset + (dstphdrs[i].p_vaddr - tmp->range.vaddr);
					break;
				}
			}

			if (dstphdrs[i].p_type == PT_PHDR) {
				/* fix up PHDR segment */
				dstphdrs[i].p_vaddr = desc->phdr_vaddr;
				dstphdrs[i].p_paddr = dstphdrs[i].p_vaddr;
				dstphdrs[i].p_offset = desc->phdr_start;
				if (elfclass == ELFCLASS32) {
					dstphdrs[i].p_filesz = desc->phdr_entries * sizeof(Elf32_Phdr);
				}
				else {
					dstphdrs[i].p_filesz = desc->phdr_entries * sizeof(Elf64_Phdr);
				}
				dstphdrs[i].p_memsz = dstphdrs[i].p_filesz;
			}
		}
	}

//---------------------------------------------------------------------------//
// Copy sections and section headers                                         //
//---------------------------------------------------------------------------//
	errno = 0;
	// current section header of input file
	GElf_Shdr *srcshdr = calloc(1, sizeof(GElf_Shdr));
	if (srcshdr == NULL) {
		error(0, errno, "Out of memory");
		goto err_free_desc;
	}
	errno = 0;
	// current section header of output file
	GElf_Shdr *dstshdr = calloc(1, sizeof(GElf_Shdr));
	if (dstshdr == NULL) {
		error(0, errno, "Out of memory");
		goto err_free_srcshdr;
	}

	// current section of input file
	Elf_Scn *srcscn = NULL;
	/* lib creates section 0 automatically so we start with section 1 */
	for (size_t i = 1; i < scnnum; i++) {
		srcscn = elf_getscn(srce, i);
		if (srcscn == NULL) {
			error(0, 0, "Could not retrieve section %lu of input file: %s", i, elf_errmsg(-1));
			goto err_free_dstshdr;
		}

		if (gelf_getshdr(srcscn, srcshdr) == NULL) {
			error(0, 0, "Could not retrieve shdr structure for section %lu of input file: %s", i, elf_errmsg(-1));
			goto err_free_dstshdr;
		}
		Elf_Scn *dstscn = elf_newscn(dste);
		if (dstscn == NULL) {
			error(0, 0, "Could not create section %lu in output file: %s", i, elf_errmsg(-1));
			goto err_free_dstshdr;
		}
		if (gelf_getshdr(dstscn, dstshdr) == NULL) {
			error(0, 0, "Could not retrieve shdr structure for section %lu of output file: %s", i, elf_errmsg(-1));
			goto err_free_dstshdr;
		}

		/* allocate buffers for the data of the output file */
		for (Chain *tmp = &section_ranges[i]; tmp; tmp = tmp->next) {
			errno = 0;
			tmp->data.buffer = calloc(tmp->data.to - tmp->data.from, sizeof(char));
			if (tmp->data.buffer == NULL) {
				error(0, errno, "Out of memory");
				goto err_free_dstshdr;
			}
		}

		// current data of current section of input file
		Elf_Data *srcdata = NULL;
		/* copy data in data buffers for output file */
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
					/* source data ends before range (and the following range
					 * because the list is sorted) begins */
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
				error(0, 0, "Could not add data to section %lu of output file: %s", i, elf_errmsg(-1));
				goto err_free_dstshdr;
			}

			/* alignment does not matter here because the position of the data
			 * range is controlled via d_off */
			dstdata->d_align = 1;
			dstdata->d_type = tmp->data.d_type;
			dstdata->d_version = tmp->data.d_version;
			dstdata->d_buf = tmp->data.buffer;
			dstdata->d_off = tmp->data.from + tmp->data.data_shift;
			dstdata->d_size = tmp->data.to - tmp->data.from;
		}

		/* construct the SHDR entry of current section */
		dstshdr->sh_info = srcshdr->sh_info;
		dstshdr->sh_name = srcshdr->sh_name;
		dstshdr->sh_type = srcshdr->sh_type;
		dstshdr->sh_addr = srcshdr->sh_addr;
		dstshdr->sh_flags = srcshdr->sh_flags;
#ifdef TESTCASE
		if (srcshdr->sh_addralign == 65536) {
			dstshdr->sh_addralign = 16;
		}
		else {
			dstshdr->sh_addralign = srcshdr->sh_addralign;
		}
#else
		dstshdr->sh_addralign = srcshdr->sh_addralign;
#endif
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
			error(0, 0, "Could not update ELF structures (Sections): %s", elf_errmsg(-1));
			goto err_free_dstshdr;
		}
	}

	dstehdr->e_shoff = desc->shdr_start;

	/* write new ELF file */
	if (elf_update(dste, ELF_C_WRITE) == -1) {
		error(0, 0, "Could not write ELF structures to output file: %s", elf_errmsg(-1));
		goto err_free_dstshdr;
	}

//---------------------------------------------------------------------------//
// Clean up                                                                  //
//---------------------------------------------------------------------------//
	free(dstshdr);
	free(srcshdr);
	deleteDesc(desc);
	free(srcphdr);

	return 0;

//---------------------------------------------------------------------------//
// Error handling                                                            //
//---------------------------------------------------------------------------//
err_free_dstshdr:
	free(dstshdr);
err_free_srcshdr:
	free(srcshdr);
err_free_desc:
	deleteDesc(desc);
err_free_srcphdr:
	free(srcphdr);
}
