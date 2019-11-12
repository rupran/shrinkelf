#include <error.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

#include "libelf/libelf.h"

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

	elf_end(srce);
	if (close(srcfd) < 0)
		error(EXIT_FAILURE, errno, "close %s failed", filename);

	return 0;

err_free_srcfd:
	if (close(srcfd) < 0)
		error(0, errno, "close %s failed", filename);
	exit(EXIT_FAILURE);
}
