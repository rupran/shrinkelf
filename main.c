#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "libelf/libelf.h"


const char *FILESUFFIX = ".shrinked";

int main(int argc, char **argv) {
	// TODO: better command line parsing
	if (argc != 2)
		error(EXIT_FAILURE, 0, "usage: %s file-name", argv[0]);

	char *filename = argv[1];

	// libelf-library won't work if you don't tell it the ELF version
	if (elf_version(EV_CURRENT) == EV_NONE)
		error(EXIT_FAILURE, 0, "ELF library initialization failed: %s", elf_errmsg(-1));

	int srcfd;	// file descriptor of source file
	if ((srcfd = open(filename, O_RDONLY)) < 0)
		error(EXIT_FAILURE, errno, "open %s failed", filename);
	Elf *srce;	// ELF representation of source file
	if ((srce = elf_begin(srcfd, ELF_C_READ, NULL)) == NULL) {
		error(0, 0, "elf_begin() failed: %s", elf_errmsg(-1));
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
		error(0, errno, "open %s failed", dstfname);
		goto err_free_srce;
	}
	Elf *dste;	// ELF representation of new file
	if ((dste = elf_begin(dstfd, ELF_C_WRITE, NULL)) == NULL) {
		error(0, 0, "elf_begin() failed: %s", elf_errmsg(-1));
		goto err_free_dstfd;
	}

	elf_end(dste);
	if (close(dstfd) < 0) {
		error(0, errno, "close %s failed", dstfname);
		goto err_free_dstfname;
	}
	free(dstfname);
	elf_end(srce);
	if (close(srcfd) < 0)
		error(EXIT_FAILURE, errno, "close %s failed", filename);

	return 0;

err_free_dstfd:
	if (close(dstfd) < 0)
		error(0, errno, "close %s failed", dstfname);
err_free_dstfname:
	free(dstfname);
err_free_srce:
	elf_end(srce);
err_free_srcfd:
	if (close(srcfd) < 0)
		error(0, errno, "close %s failed", filename);
	exit(EXIT_FAILURE);
}
