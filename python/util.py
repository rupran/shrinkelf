from ctypes import Array
from typing import List

# Fixme: Doku
PAGESIZE = 0x1000


class MemoryFragment:
    """
    information about memory layout of the enclosing FileFragment

    loadable -- flag if the fragment is part of a LOAD segment
    flags -- flags of the containing segment
    align -- alignment requirement of the containing segment
    start -- start address of the enclosing FileFragment in memory
    end -- end address (exclusive) of the enclosing FileFragment in memory
    """

    loadable: bool
    flags: int
    align: int
    start: int
    end: int

    def __init__(self, start: int = 0, end: int = 0, align: int = 0, flags: int = 0, loadable: bool = False) -> None:
        """ Initialize self.

        :param start: start address of the enclosing FileFragment in memory
        :type start: int
        :param end: end address (exclusive) of the enclosing FileFragment in memory
        :type end: int
        :param align: alignment requirement of the containing segment
        :type align: int
        :param flags: flags of the containing segment
        :type flags: int
        :param loadable: flag if the fragment is part of a LOAD segment
        :type loadable: bool
        """

        self.start = start
        self.end = end
        self.align = align
        self.flags = flags
        self.loadable = loadable


class FileFragment:
    """
    file fragment to keep

    A fragment of data that the user wants to keep. Addresses are relative to the start address of the containing
    section and based on the file representation.

    start -- start address of the file fragment relative to its containing section
    end -- end address (exclusive) of the file fragment relative to its containing section
    section_offset -- offset of the containing section in the file
    section_align -- alignment requirement of the containing section
    section_shift -- Shift of the containing section in the file. Negative values mean a shift towards the beginning of
                     the file
    fragment_shift -- Shift of the file fragment in its section. Negative values mean a shift towards the beginning of
                      the section
    buffer -- buffer for the data described by this fragment
    d_type -- value of corresponding member of Elf_Data struct from the libelf library
    d_version -- value of corresponding member of Elf_Data struct from the libelf library
    memory_info -- information regarding the memory layout of this fragment
    """

    start: int
    end: int
    section_offset: int
    section_align: int
    section_shift: int
    fragment_shift: int
    buffer: Array
    d_type: int
    d_version: int
    memory_info: MemoryFragment

    def __init__(self, start: int = 0, end: int = 0, section_offset: int = 0, section_align: int = 0,
                 section_shift: int = 0, fragment_shift: int = 0, buffer: Array = None, d_type: int = 0,
                 d_version: int = 0, memory_info: MemoryFragment = None) -> None:
        """ Initialize self.

        :param start: start address of the file fragment relative to its containing section
        :type start: int
        :param end: end address (exclusive) of the file fragment relative to its containing section
        :type end: int
        :param section_offset: offset of the containing section in the file
        :type section_offset: int
        :param section_align: alignment requirement of the containing section
        :type section_align: int
        :param section_shift: Shift of the containing section in the file. Negative values mean a shift towards the
                              beginning of the file
        :type section_shift: int
        :param fragment_shift: Shift of the file fragment in its section. Negative values mean a shift towards the
                               beginning of the section
        :type fragment_shift: int
        :param buffer: buffer for the data described by this fragment
        :type buffer: ctypes.Array[char]
        :param d_type: value of corresponding member of Elf_Data struct from the libelf library
        :type d_type: int
        :param d_version: value of corresponding member of Elf_Data struct from the libelf library
        :type d_version: int
        :param memory_info: information regarding the memory layout of this fragment
        :type memory_info: MemoryFragment
        """

        self.start = start
        self.end = end
        self.section_offset = section_offset
        self.section_align = section_align
        self.section_shift = section_shift
        self.fragment_shift = fragment_shift
        self.buffer = buffer
        self.d_type = d_type
        self.d_version = d_version
        if memory_info is None:
            self.memory_info = MemoryFragment()
        else:
            self.memory_info = memory_info

    def size(self) -> int:
        """ Return size of fragment. """

        return self.end - self.start

    def __lt__(self, other):
        return self.start < other.start


class FragmentRange:
    """
    block of file fragments that can be permuted

    Range in file that can be rearranged to save space. Rearranged means that ordering of ranges in the input file may
    not be preserved. The range can span over multiple file fragment and the room between them.  A side effect of this
    is that there need not be data behind every address in this range.
    Fragment ranges are constructed in such a way that file fragments which are loaded in the same page reside in the
    same fragment range. The rational behind this is to derive the LOAD segments of the new file from the fragment
    ranges.

    offset -- offset of the range in the input file
    fsize -- size of the range in the file representation
    vaddr -- start address of the range in memory
    msize -- size of the range in memory
    flags -- flags of the containing LOAD segment
    shift -- Shift of the range in the new file. Negative values mean a shift towards the beginning of the file
    loadable -- flag if the range is part of a LOAD segment
    section_start -- offset of the containing section in the new file
    """

    offset: int
    fsize: int
    vaddr: int
    msize: int
    flags: int
    shift: int
    loadable: bool
    section_start: int

    def __init__(self, loadable: bool = False, flags: int = 0, fsize: int = 0, msize: int = 0, offset: int = 0,
                 vaddr: int = 0, shift: int = 0, section_start: int = 0) -> None:
        """ Initialize self.

        :param loadable: flag if the range is part of a LOAD segment
        :type loadable: bool
        :param flags: flags of the containing LOAD segment
        :type flags: int
        :param fsize: size of the range in the file representation
        :type fsize: int
        :param msize: size of the range in memory
        :type msize: int
        :param offset: offset of the range in the input file
        :type offset: int
        :param vaddr: start address of the range in memory
        :type vaddr: int
        :param shift: Shift of the range in the new file. Negative values mean a shift towards the beginning of the file
        :type shift: int
        :param section_start: offset of the containing section in the new file
        :type section_start: int
        """

        self.loadable = loadable
        self.flags = flags
        self.fsize = fsize
        self.msize = msize
        self.offset = offset
        self.vaddr = vaddr
        self.shift = shift
        self.section_start = section_start
        self.contained_in = -1

    def end_in_section(self) -> int:
        """ Return end address of range relative to the start address of the containing section. """

        return self.offset + self.fsize - self.section_start

    def end_in_file(self) -> int:
        """ Return end address of range relative to the start of the file. """

        return self.offset + self.fsize

    # Fixme: Doku
    def get_smt_constants(self):
        return self.offset % PAGESIZE, self.fsize


# Fixme: Doku
class LayoutDescription:
    """
    description of the new file layout

    phdr_start -- offset of PHDR table in new file
    phdr_vaddr -- offset of PHDR table in memory after shrinking the original ELF file
    phdr_entries -- number of entries in new PHDR table
    shdr_start -- offset of SHDR table in new file
    """

    phdr_start: int
    phdr_vaddr: int
    phdr_entries: int
    shdr_start: int
    segments: List[List[FragmentRange]]
    segment_num: int
    segment_list: List[FragmentRange]
    list_entries: int
    phdr_in_section: int

    # Fixme: Doku
    def __init__(self, list_entries: int = 0, segment_num: int = 0, segments: List[List[FragmentRange]] = None,
                 segment_list: List[FragmentRange] = None, phdr_vaddr: int = 0, phdr_start: int = 0,
                 phdr_entries: int = 0, shdr_start: int = 0, phdr_in_section: int = 0) -> None:
        """ Initialize self.

        :param list_entries:
        :type list_entries:
        :param segment_num:
        :type segment_num:
        :param segments:
        :type segments:
        :param segment_list:
        :type segment_list:
        :param phdr_vaddr: offset of PHDR table in memory after shrinking the original ELF file
        :type phdr_vaddr: int
        :param phdr_start: offset of PHDR table in new file
        :type phdr_start: int
        :param phdr_entries: number of entries in new PHDR table
        :type phdr_entries: int
        :param shdr_start: offset of SHDR table in new file
        :type shdr_start: int
        :param phdr_in_section: index in the mid of which section the PHDR table lies
        :type phdr_in_section: int
        """

        if segment_list is None:
            segment_list = []
        if segments is None:
            segments = []
        self.list_entries = list_entries
        self.segment_num = segment_num
        self.segments = segments
        self.segment_list = segment_list
        self.phdr_vaddr = phdr_vaddr
        self.phdr_start = phdr_start
        self.phdr_entries = phdr_entries
        self.shdr_start = shdr_start
        self.phdr_in_section = phdr_in_section

    def sorted_loadable_segments(self) -> List[FragmentRange]:
        """ Return a list of the loadable fragment ranges (which will provide the data for the new LOAD segments). """

        ret: List[FragmentRange] = []
        for elem in self.segment_list:
            if elem.loadable:
                ret.append(elem)
        ret.sort(key=lambda item: item.vaddr)
        return ret


class Permutation:
    """
    permutation of fragment ranges

    tmp -- array of indexes, describing the current permutation
    result -- array of indexes, describing the current optimum
    num_entries -- size of the arrays
    size -- size of the fragment ranges in ordering of the current optimum
    """

    tmp: List[int]
    result: List[int]
    num_entries: int
    size: int

    def __init__(self, result: List[int] = None, size: int = 0, num_entries: int = 0, tmp: List[int] = None) -> None:
        """ Initialize self.

        :param result: array of indexes, describing the current optimum
        :type result: List[int]
        :param size: size of the fragment ranges in ordering of the current optimum
        :type size: int
        :param num_entries: size of the arrays
        :type num_entries: int
        :param tmp: array of indexes, describing the current permutation
        :type tmp: List[int]
        """
        self.result = result
        self.size = size
        self.tmp = tmp
        self.num_entries = num_entries
