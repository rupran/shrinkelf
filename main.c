#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "libelf/libelf.h"
#include "libelf/gelf.h"


// TODO: better error messages
const char *FILESUFFIX = ".shrinked";

// TODO: better wording
/*
 * sets e_ident, e_machine, e_type and e_flags for the new file
 *
 * e_ehsize, e_phentsize, e_shentsize, e_phnum and e_shnum are set by libelf
 *
 * does set e_entry, e_phoff, e_shoff and e_shstrndx - as fall back
 */
int copy_header_info(Elf *srce, Elf *dste) {
	int elfclass;		//ELF class of source file
	if ((elfclass = gelf_getclass(srce)) == ELFCLASSNONE) {
		error(0, 0, "could not retrieve ELF class from source file");
		return -1;
	}
	// executable header of source file
	GElf_Ehdr *srcehdr = calloc(1, sizeof(GElf_Ehdr));
	if(srcehdr == NULL) {
		error(0, errno, "unable to allocate memory for executable header of source file");
		return -1;
	}
	if (gelf_getehdr(srce, srcehdr) == NULL) {
		error(0, 0, "could not retrieve executable header from source file: %s",
		      elf_errmsg(-1));
		goto err_free_srcehdr;
	}
	// executable header of new file
	GElf_Ehdr *dstehdr = calloc(1, sizeof(GElf_Ehdr));
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
	if (elf_update(dste, ELF_C_NULL) == -1) {
		error(0, 0, "could not update ELF structures (Header): %s",
		      elf_errmsg(-1));
		goto err_free_dstehdr;
	}


	free(dstehdr);
	free(srcehdr);
	return 0;

err_free_dstehdr:
	free(dstehdr);
err_free_srcehdr:
	free(srcehdr);
	return -1;
}

int main(int argc, char **argv) {
	// TODO: better command line parsing
	if (argc != 2)
		error(EXIT_FAILURE, 0, "usage: %s file-name", argv[0]);

	char *filename = argv[1];

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
	char *dstfname = calloc(fnamesz, sizeof(char));
	if(dstfname == NULL) {
		error(0, errno, "unable to allocate memory for filename");
		goto err_free_srce;
	}
	strncpy(dstfname, filename, strlen(filename));
	strncat(dstfname, FILESUFFIX, strlen(FILESUFFIX));

	int dstfd;	// file descriptor of new file
	if ((dstfd = open(dstfname, O_WRONLY | O_CREAT, 0777)) < 0) {
		error(0, errno, "unable to open %s", dstfname);
		goto err_free_srce;
	}
	Elf *dste;	// ELF representation of new file
	if ((dste = elf_begin(dstfd, ELF_C_WRITE, NULL)) == NULL) {
		error(0, 0, "could not create ELF structures for new file: %s",
		      elf_errmsg(-1));
		goto err_free_dstfd;
	}

	unsigned int flags = 0;
	if ((flags = elf_flagelf(dste, ELF_C_SET, ELF_F_LAYOUT)) == 0) {
		error(0, 0, "elf_flagelf() failed: %s.", elf_errmsg(-1));
		goto err_free_dste;
	}

	int elfclass;		//ELF class of source file
	if ((elfclass = gelf_getclass(srce)) == ELFCLASSNONE) {
		error(0, 0, "could not retrieve ELF class from source file");
		return -1;
	}
	// executable header of source file
	GElf_Ehdr *srcehdr = calloc(1, sizeof(GElf_Ehdr));
	if(srcehdr == NULL) {
		error(0, errno, "unable to allocate memory for executable header of source file");
		return -1;
	}
	if (gelf_getehdr(srce, srcehdr) == NULL) {
		error(0, 0, "could not retrieve executable header from source file: %s",
		      elf_errmsg(-1));
		// FIXME:
		goto err_free_srce;
	}
	// executable header of new file
	GElf_Ehdr *dstehdr = calloc(1, sizeof(GElf_Ehdr));
	if(dstehdr == NULL) {
		error(0, errno, "unable to allocate memory for executable header of new file");
		// FIXME:
		goto err_free_srce;
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
		// FIXME:
		goto err_free_dste;
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
		// FIXME:
		goto err_free_dste;
	}
	if (elf_update(dste, ELF_C_NULL) == -1) {
		error(0, 0, "could not update ELF structures (Header): %s",
		      elf_errmsg(-1));
		// FIXME:
		goto err_free_dste;
	}

	// FIXME: comments!
	size_t scnnum = 0;		// number of sections in source file
	if (elf_getshdrnum(srce, &scnnum) != 0) {
		error(0, 0, "could not retrieve number of sections from source file: %s",
		      elf_errmsg(-1));
		goto err_free_dste;
	}
	Elf_Scn *srcscn = NULL;
	// lib creates section 0 automatically
	for (size_t i = 1; i < scnnum; i++) {
		srcscn = elf_getscn(srce, i);
		if (srcscn == NULL)
			goto err_free_dste;

		GElf_Shdr *srcshdr = calloc(1, sizeof(GElf_Shdr));
		if (srcshdr == NULL) {
			error(0, errno, "unable to allocate memory for source shdr structure");
			goto err_free_dste;
		}
		if (gelf_getshdr(srcscn, srcshdr) == NULL) {
			error(0, 0, "could not retrieve source shdr structure for section %lu: %s",
			      i, elf_errmsg(-1));
			free(srcshdr);
			goto err_free_dste;
		}
		Elf_Scn *dstscn = elf_newscn(dste);
		if (dstscn == NULL) {
			error(0, 0, "could not create section %lu: %s", i,
			      elf_errmsg(-1));
			free(srcshdr);
			goto err_free_dste;
		}
		GElf_Shdr *dstshdr = calloc(1, sizeof(GElf_Shdr));
		if (dstshdr == NULL) {
			error(0, errno, "unable to allocate memory for new shdr structure");
			free(srcshdr);
			goto err_free_dste;
		}
		if (gelf_getshdr(dstscn, dstshdr) == NULL) {
			error(0, 0, "could not retrieve new shdr structure for section %lu: %s",
			      i, elf_errmsg(-1));
			free(dstshdr);
			free(srcshdr);
			goto err_free_dste;
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

		Elf_Data *srcdata = NULL;
		while ((srcdata = elf_getdata(srcscn, srcdata)) != NULL) {
			Elf_Data *dstdata = elf_newdata(dstscn);
			if (dstdata == NULL) {
				error(0, 0, "could not add data to section %lu: %s",
				      i, elf_errmsg(-1));
				free(dstshdr);
				free(srcshdr);
				goto err_free_dste;
			}
			dstdata->d_align = srcdata->d_align;
			dstdata->d_buf = srcdata->d_buf;
			dstdata->d_off = srcdata->d_off;
			dstdata->d_size = srcdata->d_size;
			dstdata->d_type = srcdata->d_type;
			dstdata->d_version = srcdata->d_version;
		}
		if (gelf_update_shdr(dstscn, dstshdr) == 0) {
			error(0, 0, "could not update ELF structures (Sections): %s",
			      elf_errmsg(-1));
			free(dstshdr);
			free(srcshdr);
			goto err_free_dste;
		}
	}
	// segments
	size_t phdrnum = 0;		// number of segments in source file
	if (elf_getphdrnum(srce, &phdrnum) != 0) {
		error(0, 0, "could not retrieve number of segments from source file: %s",
		      elf_errmsg(-1));
		goto err_free_dste;
	}
	GElf_Phdr *srcphdr = malloc(sizeof(GElf_Phdr));
	if (srcphdr == NULL) {
		error(0, errno, "ran out of memory");
		goto err_free_dste;
	}
	GElf_Phdr *dstphdrs = gelf_newphdr(dste, phdrnum);
	if (dstphdrs == NULL) {
		error(0, 0, "gelf_newphdr() failed: %s", elf_errmsg(-1));
		free(srcphdr);
		goto err_free_dste;
	}
	for (size_t i = 0; i < phdrnum; i++) {
		GElf_Phdr *tmp = gelf_getphdr(srce, i, srcphdr);
		if (tmp == NULL) {
			error(0, 0, "could not retrieve source phdr structure %lu: %s",
			      i, elf_errmsg(-1));
			free(srcphdr);
			goto err_free_dste;
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
		free(srcphdr);
		goto err_free_dste;
	}

	// tidy up
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
