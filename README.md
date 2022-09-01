# shrinkelf: a tool to shrink ELF files

<p align="center">
<img src="https://user-images.githubusercontent.com/6428272/187918585-cbefdc1b-ed14-4e37-8636-ae36d06cda4e.png" width="640" />
</p>


## Description
shrinkelf is a tool to shrink the disk size of ELF files to a minimal size
after unused functions and their associated metadata (symbol table entries,
relocations) have been removed while keeping the loaded memory layout identical
to the original file. It is the final step in an ELF tailoring toolchain
consisting of the analysis with
[`librarytrader`](https://github.com/rupran/librarytrader) and the overwriting
of functions and rewriting the ELF metadata structures with
[`elfremove`](https://github.com/rupran/elfremove).

## Usage
```
./shrinkelf.py [-h] [-k RANGE] [-K FILE] [-p {brute-force,gurobi,z3}] [-o FILE] [-l] [-d] file

positional arguments:
  file                  the file, which should be shrunk

optional arguments:
  -h, --help            show this help message and exit
  -k RANGE, --keep RANGE
                        Keep given RANGE in new file. Accepted formats are
                         'START-END'   exclusive END
                         'START:LEN'   LEN in bytes
                        with common prefixes for base
  -K FILE, --keep-file FILE
                        File to read ranges from
  -p {brute-force,gurobi,z3}, --permute {brute-force,gurobi,z3}
                        Permute fragments for potential smaller output file.
                        Option determines which method to use.
                        WARNING: brute-force is in O(n!)
  -o FILE, --output-file FILE
                        Name of the output file
  -l, --log             Output log files when using gurobi
  -d, --debug           very verbose debugging output
```

## Details
shrinkelf works by using information about which data should be kept in the
target file from the command line and rearranging the content of the sections in
the file in an optimal order with regards to section size. The ranges to be kept
can be generated from [`elfremove`](https://github.com/rupran/elfremove) when
functions are removed from the file. Additionally, gaps between sections will
automatically be filled by moving the following contents forward in the file.
Such gaps can arise when entries from the symbol table, symbol hash table or the
relocation table were removed, leading to a smaller size of the tables.

After reading the original section header table and the ranges from the command
line, shrinkelf builds an internal representation of all fragments which should
remain in the file, grouped by the section they are located in. A fragment is a
contiguous range of data (e.g., code) which can be rearranged to another place
in one piece. Additionally, fragments are grouped together if they are located
in the same page in the file as these fragments will still need to be loaded
into the same page in the output file. Due to the way memory mapping works we
can only load/`mmap()` every virtual 4-KiByte-sized page once so the contents
need to be located in the same page in the file as well.

The locations and sizes of all fragment groups are then converted into an
optimization problem (integer inequalities for z3, asymmetric TSP for gurobi)
and handed over to the corresponding solver to find the optimal arrangement of
the fragment groups, that is, the order of fragment groups in which the total
size of the containing section is minimal.

With the optimal order of fragment groups established, shrinkelf rewrites the
program header table of the ELF file in order to reconstruct the original
layout in the virtual address space from the reordered and shrunk file on disk.
This means that even though the placement of code and data in the file have
changed, the layout of the remaining contents after loading will be the same
as in the original file, with gaps where unneeded code and data were removed.
For this reason, we also do not need to patch any instructions in the ELF files
as all relative distances between instructions and data will be unchanged after
loading.

## License
shrinkelf itself is licensed under the terms of the GPLv3. The shipped
libelf.so.1 file is distributed under the [BSD
License](https://opensource.org/licenses/bsd-license.php), see the
[LICENSE.libelf.so.1](LICENSE.libelf.so.1) file.
