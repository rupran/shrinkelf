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

/*
 * sets e_ident, e_machine, e_type and e_flags for the new file
 *
 * e_ehsize, e_phentsize and e_shentsize are set by libelf
 *
 * does NOT set EI_OSABI, EI_ABIVERSION, e_entry, e_phoff, e_shoff, e_phnum,
 * e_shnum and e_shstrndx
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
		return -1;
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
	dstehdr->e_machine = srcehdr->e_machine;
	dstehdr->e_type = srcehdr->e_type;
	dstehdr->e_flags = srcehdr->e_flags;
	// TODO: comment what elf_update does to executable headers
	// nothing. watch out for broken ELF headers!
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

	if (copy_header_info(srce, dste) != 0)
		goto err_free_dste;

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
