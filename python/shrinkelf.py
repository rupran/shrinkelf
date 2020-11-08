#!/usr/bin/python3

import argparse
import os
from sys import stderr
from typing import Optional

from elfdefinitions import *
from util import *

# FIXME: Doku
# \brief File suffix for output file appended to the input file when no output file was specified
FILESUFFIX: str = ".shrinked"


# FIXME: Doku
class CleanUp(Exception):
    def __init__(self, level, exitstatus):
        self.level = level
        self.exitstatus = exitstatus


# FIXME: Doku
cu = CleanUp(0, 0)


# FIXME: Doku
def print_error(text):
    print(text, file=stderr)


# FIXME: Doku
# Inserts element `item` in sorted list of ranges and returns `None` on
# success. On failure returns the range `item` overlaps with and does NOT
# insert `item` in list
def insertTuple(item_03: (int, int), list_of_items: List[(int, int)]) -> (int, int):
    length_01 = len(list_of_items)
    if length_01 == 0:
        list_of_items.append(item_03)
        return None
    else:
        for i in range(0, length_01):
            current_item = list_of_items[i]
            if item_03[1] < current_item[0]:
                # item must be sorted in before current element
                list_of_items.insert(i, item_03)
                return None
            elif item_03[0] <= current_item[1]:
                # item overlaps with current element
                return current_item
        list_of_items.append(item_03)
        return None


# FIXME: Doku
# Inserts element `item` in sorted list of ranges and returns `None` on
# success. On failure returns the range `item` overlaps with and does NOT
# insert `item` in list
def insertRange(item_04: FileFragment, list_of_items: List[FileFragment]) -> Optional[FileFragment]:
    length_02 = len(list_of_items)
    if length_02 == 0:
        list_of_items.append(item_04)
        return None
    else:
        for i in range(0, length_02):
            current_item = list_of_items[i]
            if item_04.end < current_item.start:
                # item must be sorted in before current element
                list_of_items.insert(i, item_04)
                return None
            elif item_04.start <= current_item.end:
                # item overlaps with current element
                return current_item
        list_of_items.append(item_04)
        return None


# FIXME: Doku
# \brief Counts LOAD program headers in an ELF file
#
# \param elf The file
#
# \returns The number of LOAD program headers
def countLOADs(elf) -> int:
    count = 0

    # number of segments in file
    phdrnum = c_size_t(0)
    if libelf.elf_getphdrnum(elf, byref(phdrnum)) != 0:
        print_error("Could not retrieve number of segments from source file: " + libelf.elf_errmsg(c_int(-1)))
        raise cu

    phdr = GElf_Phdr()
    for i in range(0, phdrnum.value):
        if libelf.gelf_getphdr(elf, i, byref(phdr)) is None:
            print_error("Could not retrieve source phdr structure {0}: {1}".format(i, libelf.elf_errmsg(c_int(-1))))
            raise cu

        if phdr.p_type == PT_LOAD:
            count += 1

    return count


# FIXME: Doku
# \brief Constructs the [address ranges](@ref segmentRange) of a section
#
# \param section List of [data ranges](@ref range) of a section
# \param section_start Start address of this section in the new file
#
# \return A list of [address ranges](@ref segmentRange) fit for rearrangement
#         or `None` in case of an error
def segments(section: List[FileFragment], section_start: int) -> Optional[List[FragmentRange]]:
    if section is None or len(section) == 0:
        # XXX: Debug
        print("segments: section was none")
        return None

    ret = []

    current: FragmentRange = FragmentRange(offset=section[0].section_offset + section[0].start,
                                           fsize=section[0].end - section[0].start,
                                           vaddr=section[0].address_space_info.start,
                                           msize=section[0].address_space_info.end - section[0].address_space_info.start,
                                           flags=section[0].address_space_info.flags,
                                           loadable=section[0].address_space_info.loadable, section_start=section_start)
    for i in range(1, len(section)):
        if ((current.vaddr + current.msize) / PAGESIZE) == (section[i].address_space_info.start / PAGESIZE):
            # data of tmp range will be loaded in the same page as content of
            # current range => merge the ranges
            current.fsize = section[i].section_offset + section[i].end - current.offset
            current.msize = section[i].address_space_info.end - current.vaddr
            current.loadable |= section[i].address_space_info.loadable
            # TODO: tmp auftreiben
            current.flags |= tmp["as"]["flags"]
        else:
            # data of tmp range will not be loaded in the same page as content
            # of current range => create new range
            ret.append(current)
            current = FragmentRange(offset=section[i].section_offset + section[i].start,
                                    fsize=section[i].end - section[i].start, vaddr=section[i].address_space_info.start,
                                    msize=section[i].address_space_info.end - section[i].address_space_info.start,
                                    flags=section[i].address_space_info.flags,
                                    loadable=section[i].address_space_info.loadable, section_start=section_start)

    ret.append(current)
    # XXX: Debug
    print(ret)
    return ret


# FIXME: Doku
# \brief Counts the loadable [address ranges](@ref segmentRange) in a list
#
# \param segmentList The list
#
# \return Number of loadable [address ranges](@ref segmentRange)
def countLoadableSegmentRanges(segment_list: List[FragmentRange]):
    ret = 0
    for item_05 in segment_list:
        if item_05.loadable:
            ret += 1

    return ret


# FIXME: Doku
# \brief Constructor for ::permutation
#
# \param segments List of lists of [address ranges](@ref segmentRange)
#                 imposing constraints on the permutation
# \param index The index for which a ::permutation is constructed
# \param current_size The currently occupied size in the new file
#
# \return The new ::permutation
def createPermutation(segments, index, current_size):
    ret = {"numEntries": len(segments[index])}
    ret["tmp"] = [] * ret["numEntries"]
    ret["result"] = [] * ret["numEntries"]

    if current_size / PAGESIZE == (segments[index]["offset"] + segments[index]["fsize"]) / PAGESIZE:
        # mark first element because it is on the same page as the previous
        # section
        ret["tmp"][0] = -1
        ret["result"][0] = -1

    if index != len(segments) - 1:
        last = segments[index][-1]
        if (last["offset"] + last["fsize"]) / PAGESIZE == (segments[index + 1]["offset"] + segments[index + 1]["fsize"]) / PAGESIZE:
            # mark last element because its on the same page as the next
            # section
            ret["tmp"][-1] = -1
            ret["result"][-1] = -1

    # set size of the section under the currently best permutation -
    # conceptional - to infinity because it is not determined now
    # TODO: ggf. Vergleiche anpassen
    ret["size"] = -1

    return ret


# FIXME: Doku
# \brief Calculates offset of a section in new file.
#
# Constraint: new offset needs to be equal to prior offset modulo page size
# because LOAD segments require that `p_offset` (offset in file) is equal to
# `p_vaddr` (address in virtual address space) modulo page size.
#
# \param priorOffset Offset of section in original file
# \param occupiedSpace Number of already occupied bytes in new file
#
# \return Offset in new file
def calculateOffset(prior_offset, occupied_space):
    prior_page_offset = prior_offset % PAGESIZE
    occupied_page_offset = occupied_space % PAGESIZE
    if occupied_page_offset <= prior_page_offset:
        return occupied_space - occupied_page_offset + prior_page_offset
    else:
        return occupied_space - occupied_page_offset + prior_page_offset + PAGESIZE


# FIXME: Doku
# \brief Evaluates the current permutation of address ranges
#
# Computes the size of the section if the address ranges it contains are
# inserted in the ordering described by the current permutation. Updates the
# currently best permutation and its resulting size if needed.
#
# \param perm The [state of the permutation algorithm](@ref permutation)
#             containing the current and the best permutation
# \param segments The address ranges to insert
def evaluate(perm, segments):
    start = 0
    end = 0

    # look up for every position (ranges from 1 to the number of segments)
    # which segment to insert
    for i in range(1, perm["numEntries"] + 1):
        if i == 1 and perm["tmp"][0] == -1:
            # first position and the (in the input file) first segment is
            # marked to be inserted first
            start = segments["offset"]
            end = segments["offset"] + segments["fsize"]
            continue
        elif i == perm["numEntries"] and perm["tmp"][-1] == -1:
            # last position and the (in the input file) last segment is marked
            # to be inserted last
            tmp = segments[-1]
            end = calculateOffset(tmp["offset"], end) + tmp["fsize"]
            break
        else:
            # search the segment with the index for the current position
            for j in range(0, perm["numEntries"]):
                if i == perm["tmp"][j]:
                    tmp = segments[j]
                    if i == 1:
                        start = tmp["offset"]
                        end = tmp["offset"]

                    end = calculateOffset(tmp["offset"], end) + tmp["fsize"]

    size = end - start
    if size < perm["size"]:
        # update currently best permutation if current permutation is better
        for i in range(0, perm["numEntries"]):
            perm["result"][i] = perm["tmp"][i]

        perm["size"] = size


# FIXME: Doku
# \brief recursive backtracking algorithm for permutation of [address ranges]
# (@ref segmentRange)
#
# \param perm The state of the algorithm
# \param segments The address ranges to permute
# \param index The current position where a address range is inserted (doubles
#              as depth of recursion)
def recursive_permute(perm, segments, index):
    if index > perm["numEntries"]:
        # all address ranges are inserted
        evaluate(perm, segments)
        return

    if index == 1 and perm["tmp"][0] == -1:
        # first address range is constrained by the first element of segments
        recursive_permute(perm, segments, index + 1)
    elif index == perm["numEntries"] and perm["tmp"][-1] == -1:
        # last address range is constrained by the last element of segments
        recursive_permute(perm, segments, index + 1)
    else:
        for i in range(0, perm["numEntries"]):
            # check if range is not inserted yet
            if perm["tmp"][i] == 0:
                # insert range temporary
                perm["tmp"][i] = index
                # try every possible permutation with the remaining ranges
                recursive_permute(perm, segments, index + 1)
                # remove range to try the next for this position
                perm["tmp"][i] = 0


# FIXME: Doku
# \brief Computes the offset of the address ranges in the output file
#
# \param perm The order in which the ranges are inserted
# \param segments The ranges that are inserted
# \param current_size The already occupied size in the output file
def segmentOffsets(perm, segments, current_size):
    section_start = 0
    for i in range(1, perm["numEntries"]):
        if i == 1 and perm["result"][0] == -1:
            # the first element of segments is constrained to the first
            # position
            section_start = calculateOffset(segments["offset"], current_size)
            segments["shift"] = section_start - segments["offset"]
            segments["section_start"] = section_start
            current_size = section_start + segments["fsize"]
        elif i == perm["numEntries"] and perm["result"][-1] == -1:
            # the last element of segments is constrained to the last position
            tmp = segments[-1]
            tmp["shift"] = calculateOffset(tmp["offset"], current_size) - tmp["offset"]
            tmp["section_start"] = section_start
        else:
            # search the element with the matching index for the current
            # position
            for j in range(0, perm["numEntries"]):
                if i == perm["result"][j]:
                    tmp = segments[j]
                    if i == 1:
                        section_start = calculateOffset(tmp["offset"], current_size)

                    tmp["shift"] = calculateOffset(tmp["offset"], current_size) - tmp["offset"]
                    tmp["section_start"] = section_start
                    current_size = calculateOffset(tmp["offset"], current_size) + tmp["fsize"]


# FIXME: Doku
# \brief Permutes the address ranges for all sections
#
# \param segments Array of list of address ranges
# \param size Size of `segments`
# \param current_size The currently occupied space in the output file
#
# \return The size of the output file after inserting all address ranges
def permute(segments, size, current_size):
    for i in range(1, size):
        perm = createPermutation(segments, i, current_size)
        # permute the address ranges of section i
        recursive_permute(perm, segments[i], 1)
        # calculate the offsets of the address ranges of section i
        segmentOffsets(perm, segments[i], current_size)
        # update current size
        current_size = segments[i]["section_start"] + perm["size"]

    return current_size


# FIXME: Doku
# \brief Rounds up `value` to the next multiple of `base`
#
# Computes a value `x` such that `x % base == 0`, `x >= value` and `x` is minimal.
#
# \param value The value for which the next bigger multiple is computed
# \param base The value of which the multiple is computed
#
# \returns The multiple of base
def roundUp(value, base):
    tmp = value % base
    if tmp != 0:
        return value - tmp + base
    else:
        return value


# FIXME: Doku
# \brief Checks if a [address range](@ref segmentRange) contains a [data range](@ref range)
#
# \param segment The address range
# \param range The data range
#
# \return Value indicating if the address range contains the data range
def contains(segment, datarange):
    if datarange["data"]["section_offset"] + datarange["data"]["to"] <= segment["offset"] + segment["fsize"] and datarange["data"]["section_offset"] + datarange["data"]["from"] >= segment["offset"]:
        return True
    return False


# FIXME: Doku
# \brief Computes the section and data shift of all [data ranges](@ref range)
#        from the shift of the [address range](@ref segmentRange)
#
# \param ranges Array of list of [data ranges](@ref range)
# \param segments Array of list of [address ranges](@ref segmentRange)
# \param size Size of these arrays
def calculateShift(ranges, segments, size):
    for i in range(1, size):
        for tmp in segments[i]:
            for tmpSec in ranges[i]:
                if contains(tmp, tmpSec):
                    tmpSec["data"]["section_shift"] = tmp["section_start"] - tmpSec["data"]["section_offset"]
                    tmpSec["data"]["data_shift"] = tmp["shift"] - tmpSec["data"]["section_shift"]


# FIXME: Doku
def calculatePHDRInfo(fileoffset, memoryoffset, elfclass, add_ehdr):
    if elfclass == ELFCLASS32:
        realfileoffset = fileoffset if not add_ehdr else fileoffset + sizeof_elf32_ehdr
        realmemoryoffset = memoryoffset if not add_ehdr else memoryoffset + sizeof_elf32_ehdr
        phdr_start = roundUp(realfileoffset, PHDR32ALIGN)
        phdr_vaddr = roundUp(realmemoryoffset, PHDR32ALIGN)
        entry_size = sizeof_elf32_phdr
    else:
        realfileoffset = fileoffset if not add_ehdr else fileoffset + sizeof_elf64_ehdr
        realmemoryoffset = memoryoffset if not add_ehdr else memoryoffset + sizeof_elf64_ehdr
        phdr_start = roundUp(realfileoffset, PHDR64ALIGN)
        phdr_vaddr = roundUp(realmemoryoffset, PHDR64ALIGN)
        entry_size = sizeof_elf64_phdr

    return phdr_start, phdr_vaddr, entry_size


# FIXME: Doku
def mergeFragments(fragments, start_with_ehdr):
    ret = []
    current = {}

    if start_with_ehdr:
        current["offset"] = 0
        current["fsize"] = fragments[0]["offset"] + fragments[0]["shift"] + fragments[0]["fsize"]
        current["vaddr"] = (fragments[0]["vaddr"] / PAGESIZE) * PAGESIZE
        current["msize"] = current["fsize"]
        current["flags"] = fragments[0]["flags"]
        current["loadable"] = True
    else:
        current["offset"] = fragments[0]["offset"]
        current["fsize"] = fragments[0]["fsize"]
        current["vaddr"] = fragments[0]["vaddr"]
        current["msize"] = fragments[0]["msize"]
        current["flags"] = fragments[0]["flags"]
        current["loadable"] = fragments[0]["loadable"]

    for item in fragments[1:]:
        # last memory page with content from the current range
        current_page = (current["vaddr"] + current["msize"]) / PAGESIZE
        # FIXME: Doku
        # first memory page with content from the item range
        tmp_page = item["vaddr"] / PAGESIZE
        # last file page with content from the current range
        current_file_page = (current["offset"] + current["fsize"]) / PAGESIZE
        # FIXME: Doku
        # first file page with content from the item range
        tmp_file_page = (item["offset"] + item["shift"]) / PAGESIZE

        if current_page == tmp_page or (current_page + 1 == tmp_page and current_file_page + 1 == tmp_file_page):
            # FIXME: Doku
            # data of tmp range will be loaded in the same or the following
            # page as content of current range => merge the ranges
            current["fsize"] = item["offset"] + item["shift"] + item["fsize"] - current["offset"]
            current["msize"] = item["vaddr"] + item["msize"] - current["vaddr"]
            current["loadable"] |= item["loadable"]
            current["flags"] |= item["flags"]
        else:
            # FIXME: Doku
            # data of tmp range will be loaded in a page farther away from the
            # content of current range => create new ranges
            ret.append(current)
            current = {"offset": item["offset"] + item["shift"], "fsize": item["fsize"], "vaddr": item["vaddr"],
                       "msize": item["msize"], "flags": item["flags"], "loadable": item["loadable"]}

    ret.append(current)
    return ret


# FIXME: Doku
def insertPHDR(segment_list, elfclass, phdr_entries, current_size):
    for i in range(0, len(segment_list) + 1):
        if i == 0:
            current_item = segment_list[i]
            phdr_start, phdr_vaddr, entry_size = calculatePHDRInfo(0, current_item["vaddr"], elfclass, True)
            if phdr_vaddr + entry_size * phdr_entries > current_item["vaddr"]:
                # PHDR table would overlap with following fragment
                continue
            else:
                # insert PHDR table after file header
                # TODO: phdr_entries enthalten ggf. nur die Nicht-LOADs
                phdr = {"offset": phdr_start, "fsize": phdr_entries * entry_size, "vaddr": phdr_vaddr, "loadable": True}
                phdr["msize"] = phdr["fsize"]
                # TODO: Flags setzen
                # phdr["flags"] =
                # TODO: ggf. restliche fragmente in der Datei verschieben
                if current_item["offset"] + current_item["shift"] < phdr["offset"] + phdr["fsize"]:
                    shift = roundUp(phdr["offset"] + phdr["fsize"] - (current_item["offset"] + current_item["shift"]), PAGESIZE)
                    for j in range(i, len(segment_list)):
                        tmp3 = segment_list[j]
                        tmp3["shift"] += shift
                        tmp3["section_start"] += shift
                    # TODO: current_size kommunizieren
                    current_size += shift
                    # correct offset of LOAD PHDRs after inserting PHDR table
                    # TODO: ist das nötig?
                    current_item["fsize"] += shift
                # TODO: in segment_list einhängen
                segment_list.insert(i, phdr)
                mergeFragments(segment_list, False)
                # TODO: PHDR info zurückgeben
                return phdr
        # TODO:
        elif i == len(segment_list):
            previous_item = segment_list[i - 1]
            fileoffset = previous_item["offset"] + previous_item["fsize"] + previous_item["shift"]
            memoryoffset = previous_item["vaddr"] + previous_item["msize"]
            phdr_start, phdr_vaddr, entry_size = calculatePHDRInfo(fileoffset, memoryoffset, elfclass, False)
            # insert after all sections
            # XXX: untested
            # FIXME: Alignment not given after NOBITS sections
            phdr = {"offset": phdr_start, "vaddr": phdr_vaddr, "fsize": phdr_entries * entry_size, "loadable": True}
            phdr["msize"] = phdr["fsize"]
            # TODO: Flags setzen
            # phdr["flags"] =
            # TODO: current_size kommunizieren
            current_size = phdr["offset"] + phdr["fsize"]
            # TODO: in segment_list einhängen
            segment_list.append(phdr)
            mergeFragments(segment_list, False)
            # TODO: Sprungmarke fixen
            return phdr
        else:
            previous_item = segment_list[i - 1]
            current_item = segment_list[i]
            # determine which start addresses the PHDR table would have if it were
            # inserted after section i
            fileoffset = previous_item["offset"] + previous_item["fsize"] + previous_item["shift"]
            memoryoffset = previous_item["vaddr"] + previous_item["msize"]
            phdr_start, phdr_vaddr, entry_size = calculatePHDRInfo(fileoffset, memoryoffset, elfclass, False)
            if phdr_vaddr + entry_size * phdr_entries > current_item["vaddr"]:
                # PHDR table would overlap with following fragment
                continue
            else:
                # insert PHDR table after file header
                phdr = {"offset": phdr_start, "fsize": phdr_entries * entry_size, "vaddr": phdr_vaddr, "loadable": True}
                phdr["msize"] = phdr["fsize"]
                # TODO: Flags setzen
                # phdr["flags"] =
                # TODO: ggf. restliche fragmente in der Datei verschieben
                if current_item["offset"] + current_item["shift"] < phdr["offset"] + phdr["fsize"]:
                    shift = roundUp(phdr["offset"] + phdr["fsize"] - (current_item["offset"] + current_item["shift"]), PAGESIZE)
                    for j in range(i, len(segment_list)):
                        tmp3 = segment_list[j]
                        tmp3["shift"] += shift
                        tmp3["section_start"] += shift
                    # TODO: current_size kommunizieren
                    current_size += shift
                    # correct offset of LOAD PHDRs after inserting PHDR table
                    # TODO: ist das nötig?
                    current_item["fsize"] += shift
                # TODO: in segment_list einhängen
                segment_list.insert(i, phdr)
                mergeFragments(segment_list, False)
                # TODO: PHDR info zurückgeben
                return phdr


# FIXME: Doku
# \brief Calculates the new file layout
#
# \param ranges Array of list of data ranges to incorporate in the new file
# \param size Size of ranges
# \param oldEntries Number of PHDR entries of original file that are NOT LOADs
# \param elfclass Elf Class (32bit or 64bit)
# \param permuteRanges Flag if the address ranges of sections should be permuted
#
# \return The [description of the file layout](@ref layoutDescription) of the
#         output file
def calculateNewFilelayout(ranges, size, old_entries, elfclass, permute_ranges) -> LayoutDescription:
    ret: LayoutDescription = LayoutDescription(segment_num=size)

    # number of LOAD entries in new PHDR table
    # Start with one for file header and one for PHDR table
    loads = 2
    # TODO: wofür wirst du gebraucht?
    current_size = 0
    if elfclass == ELFCLASS32:
        current_size = sizeof_elf32_ehdr
    else:
        current_size = sizeof_elf64_ehdr

    segments = [[]] * size
    # ignore section 0 (that is not a "real" section)
    for i in (1, size):
        # determine the address ranges from the data ranges of a section
        segments[i] = segments(ranges[i], ranges[i][0]["data"]["section_offset"])
        loads += countLoadableSegmentRanges(segments[i])

    ret.segments = segments

    # check if user want to permute address ranges
    if permute_ranges:
        current_size = permute(ret.segments, ret.segment_num, current_size)
        if current_size == 0:
            raise cu
    else:
        # simply push the address ranges together
        for i in range(1, size):
            section_start = calculateOffset(ret.segments[i][0].section_start, current_size)
            for item in ret.segments[i]:
                item["shift"] = calculateOffset(item["offset"], current_size) - item["offset"]
                item["section_start"] = section_start
                current_size = calculateOffset(item["offset"], current_size) + item["fsize"]

    # join address ranges between sections
    fragments = []
    for i in range(1, size):
        fragments += ret.segments[i]

    ret.segment_list = mergeFragments(fragments, True)
    ret.list_entries = len(ret.segment_list)

    # TODO: phdr kommunizieren
    phdr = insertPHDR(ret.segment_list, elfclass, ret.list_entries + old_entries, current_size)
    calculateShift(ranges, ret.segments, size)

    # determine start of SHDR table
    if elfclass == ELFCLASS32:
        ret.shdr_start = roundUp(current_size, SHDR32ALIGN)
    else:
        ret.shdr_start = roundUp(current_size, SHDR64ALIGN)
    return ret


# FIXME: Doku
# \brief Computes the ranges to keep per section
#
# \param src Original ELF file to get data about sections
# \param ranges Ranges specified via command line
# \param section_number Number of sections in `src`
#
# \return a List of lists containing the ranges (with additional information)
#         per section
def computeSectionRanges(src, ranges, section_number) -> List[List[FileFragment]]:
    # number of segments in source file
    phdrnum: c_size_t[int] = c_size_t(0)
    if libelf.elf_getphdrnum(src, byref(phdrnum)) != 0:
        print_error("Could not retrieve number of segments from source file: " + libelf.elf_errmsg(c_int(-1)))
        raise cu

    # current range to process
    r: int = 0
    # ranges split per section
    section_ranges: List[List[FileFragment]] = [None] * section_number.value
    for i in range(0, section_number.value):
        section_ranges[i] = []

        srcscn: c_void_p = libelf.elf_getscn(src, c_int(i))
        if srcscn is None:
            print_error("Could not retrieve source section data for section {0}: {1}".format(i, libelf.elf_errmsg(c_int(-1))))
            raise cu

        srcshdr = GElf_Shdr()
        if libelf.gelf_getshdr(srcscn, byref(srcshdr)) is None:
            print_error("Could not retrieve source shdr data for section {0}: {1}".format(i, libelf.elf_errmsg(c_int(-1))))
            raise cu

        # split ranges in section ranges and add layout data (ranges that end
        # in section i)
        while r < len(ranges) and ranges[r][1] <= srcshdr.sh_offset + (0 if srcshdr.sh_type == SHT_NOBITS else srcshdr.sh_size):
            current_fragment = FileFragment()

            # determine start and end addresses of section range in file
            if srcshdr.sh_type == SHT_NOBITS:
                # NOBITS section don't have data in file
                current_fragment.start = 0
                current_fragment.end = 0
            else:
                # determine start of range under construction relative to the
                # start of its containing section
                if ranges[r][0] < srcshdr.sh_offset:
                    # range under construction starts at the beginning of its
                    # containing section
                    current_fragment.start = 0
                else:
                    current_fragment.start = ranges[r][0] - srcshdr.sh_offset

                # determine end of range under construction relative to the end
                # of its containing section
                if ranges[r][1] < srcshdr.sh_offset + srcshdr.sh_size:
                    current_fragment.end = ranges[r][1] - srcshdr.sh_offset
                else:
                    # range under construction ends at the end of its
                    # containing section
                    current_fragment.end = srcshdr.sh_size

                if srcshdr.sh_entsize != 0 and current_fragment.start % srcshdr.sh_entsize != 0:
                    print_error("In section {0}: range to keep is misaligned by {1} byte(s) (start relative to section start: 0x{2:x}, entrysize: 0x{3:x}, start of problematic range to keep: 0x{4:x})".format(i, current_fragment.start % srcshdr.sh_entsize, current_fragment.start, srcshdr.sh_entsize, current_fragment.start + srcshdr.sh_offset))
                    raise cu

                if srcshdr.sh_entsize != 0 and current_fragment.end % srcshdr.sh_entsize != 0:
                    print_error("In section {0}: range to keep is misaligned by {1} byte(s) (end relative to section start: 0x{2:x}, entrysize: 0x{3:x}, end of problematic range to keep: 0x{4:x})".format(i, current_fragment.end % srcshdr.sh_entsize, current_fragment.end, srcshdr.sh_entsize, current_fragment.end + srcshdr.sh_offset))
                    raise cu

            current_fragment.section_align = srcshdr.sh_addralign
            current_fragment.section_offset = srcshdr.sh_offset

            # memory layout of section range
            for j in range(0, phdrnum.value):
                srcphdr = GElf_Phdr()
                if libelf.gelf_getphdr(src, c_int(j), byref(srcphdr)) is None:
                    print_error("Could not retrieve source phdr structure {0}: {1}".format(i, libelf.elf_errmsg(c_int(-1))))
                    raise cu

                if srcphdr.p_type != PT_LOAD:
                    # not a loadable segment so it contains no data about the
                    # memory layout of any part of the input file
                    continue

                if srcphdr.p_offset >= srcshdr.sh_offset + (0 if srcshdr.sh_type == SHT_NOBITS else srcshdr.sh_size) or srcphdr.p_offset + (srcphdr.p_memsz if srcshdr.sh_type == SHT_NOBITS else srcphdr.p_filesz) <= srcshdr.sh_offset:
                    # loadable segment but does not load this section
                    continue

                current_fragment.address_space_info.loadable = True
                current_fragment.address_space_info.flags = srcphdr.p_flags
                current_fragment.address_space_info.align = srcphdr.p_align

                if srcshdr.sh_type == SHT_NOBITS:
                    # range contains whole NOBITS section
                    current_fragment.address_space_info.start = srcshdr.sh_addr
                    current_fragment.address_space_info.to = current_fragment.address_space_info.start + srcshdr.sh_size
                else:
                    # determine start and end addresses of section range in memory
                    if srcphdr.p_offset <= srcshdr.sh_offset:
                        # segment starts before section starts
                        current_fragment.address_space_info.start = srcphdr.p_vaddr + srcshdr.sh_offset + current_fragment.start - srcphdr.p_offset
                    else:
                        # segment starts after section starts
                        current_fragment.address_space_info.start = srcphdr.p_offset - srcshdr.sh_offset

                    current_fragment.address_space_info.end = current_fragment.address_space_info.start + (current_fragment.end - current_fragment.start)

                break

            insertRange(current_fragment, section_ranges[i])
            r += 1

        # split ranges in section ranges and add layout data (range that begins
        # in section i but does not end there)
        if r < len(ranges) and ranges[r][0] < srcshdr.sh_offset + (0 if srcshdr.sh_type == SHT_NOBITS else srcshdr.sh_size):
            current_fragment = FileFragment()

            # determine start and end addresses of section range in file
            if srcshdr.sh_type == SHT_NOBITS:
                # NOBITS section don't have data in file
                current_fragment.start = 0
                current_fragment.end = 0
            else:
                # determine start of range under construction relative to the
                # start of its containing section
                if ranges[r][0] < srcshdr.sh_offset:
                    # range under construction starts at the beginning of its
                    # containing section
                    current_fragment.start = 0
                else:
                    current_fragment.start = ranges[r][0] - srcshdr.sh_offset
                # range under construction ends at the end of its containing
                # section
                current_fragment.end = srcshdr.sh_size

                if srcshdr.sh_entsize != 0 and current_fragment.start % srcshdr.sh_entsize != 0:
                    print_error("In section {0}: range to keep is misaligned by {1} byte(s) (start relative to section start: 0x{2:x}, entrysize: 0x{3:x}, start of problematic range to keep: 0x{4:x})".format(i, current_fragment.start % srcshdr.sh_entsize, current_fragment.start, srcshdr.sh_entsize, current_fragment.start + srcshdr.sh_offset))
                    raise cu

                if srcshdr.sh_entsize != 0 and current_fragment.end % srcshdr.sh_entsize != 0:
                    print_error("In section {0}: range to keep is misaligned by {1} byte(s) (end relative to section start: 0x{2:x}, entrysize: 0x{3:x}, end of problematic range to keep: 0x{4:x})".format(i, current_fragment.end % srcshdr.sh_entsize, current_fragment.end, srcshdr.sh_entsize, current_fragment.end + srcshdr.sh_offset))
                    raise cu

            current_fragment.section_align = srcshdr.sh_addralign
            current_fragment.section_offset = srcshdr.sh_offset

            # memory layout of section range
            for j in range(0, phdrnum.value):
                srcphdr = GElf_Phdr()
                if libelf.gelf_getphdr(src, c_int(j), byref(srcphdr)) is None:
                    print_error("Could not retrieve source phdr structure {0}: {1}".format(i, libelf.elf_errmsg(c_int(-1))))
                    raise cu

                if srcphdr.p_type != PT_LOAD:
                    # not a loadable segment so it contains no data about the
                    # memory layout of any part of the input file
                    continue

                if srcphdr.p_offset >= srcshdr.sh_offset + (0 if srcshdr.sh_type == SHT_NOBITS else srcshdr.sh_size) or srcphdr.p_offset + (srcphdr.p_memsz if srcshdr.sh_type == SHT_NOBITS else srcphdr.p_filesz) <= srcshdr.sh_offset:
                    # loadable segment but does not load this section
                    continue

                current_fragment.address_space_info.loadable = True
                current_fragment.address_space_info.flags = srcphdr.p_flags
                current_fragment.address_space_info.align = srcphdr.p_align

                if srcshdr.sh_type == SHT_NOBITS:
                    # range contains whole NOBITS section
                    current_fragment.address_space_info.start = srcshdr.sh_addr
                    current_fragment.address_space_info.end = current_fragment.address_space_info.start + srcshdr.sh_size
                else:
                    # determine start and end addresses of section range in memory
                    if srcphdr.p_offset <= srcshdr.sh_offset:
                        # segment starts before section starts
                        current_fragment.address_space_info.start = srcphdr.p_vaddr + srcshdr.sh_offset + current_fragment.start - srcphdr.p_offset
                    else:
                        # segment starts after section starts
                        current_fragment.address_space_info.start = srcphdr.p_offset - srcshdr.sh_offset

                    current_fragment.address_space_info.end = current_fragment.address_space_info.start + (current_fragment.end - current_fragment.start)

                break

            insertRange(current_fragment, section_ranges[i])

    return section_ranges


# FIXME: Doku
# \brief Calculates the size of a section
#
# \param section List of data ranges in a section
#
# \return The size of the section
def calculateSectionSize(section):
    size = 0
    for tmp in section:
        temp_size = tmp["data"]["to"] + tmp["data"]["data_shift"]
        if temp_size > size:
            size = temp_size

    return size


# FIXME: Doku
def shrinkelf(args, ranges):
    # --------------------------------------------------------------------------- #
    #  Setup                                                                      #
    # --------------------------------------------------------------------------- #
    # libelf-library won't work if you don't tell it the ELF version
    if libelf.elf_version(EV_CURRENT) == EV_NONE:
        print_error("ELF library initialization failed: " + libelf.elf_errmsg(c_int(-1)))
        exit(1)

    # file descriptor of input file
    # TODO: Rückgabewert von os.open nachschlagen
    srcfd = os.open(args.file, os.O_RDONLY)
    if srcfd < 0:
        print_error("Could not open input file " + args.file)
        exit(1)

    cu.level += 1
    try:
        # ELF representation of input file
        srce: c_void_p = libelf.elf_begin(c_int(srcfd), ELF_C_READ, None)
        if srce is None:
            print_error("Could not retrieve ELF structures from input file: " + libelf.elf_errmsg(c_int(-1)))
            raise cu

        cu.level += 1
        # file descriptor of output file
        # TODO: Rückgabewert von os.open nachschlagen
        dstfd: int = os.open(args.output_file, os.O_WRONLY | os.O_CREAT, mode=0o777)
        if dstfd < 0:
            print_error("Could not open output file " + args.output_file)
            raise cu

        cu.level += 1
        # ELF representation of output file
        dste: c_void_p = libelf.elf_begin(c_int(dstfd), ELF_C_WRITE, None)
        if dste is None:
            print_error("Could not create ELF structures for output file: " + libelf.elf_errmsg(c_int(-1)))
            raise cu

        cu.level += 1
        # tell lib that the application will take care of the exact file layout
        if libelf.elf_flagelf(dste, ELF_C_SET, ELF_F_LAYOUT) == 0:
            print_error("elf_flagelf() failed: " + libelf.elf_errmsg(c_int(-1)))
            raise cu

        # Specify fill byte for padding -- especially the padding within the
        # .text section. Set to 0xcc because this generates an interrupt on the
        # target platform x86_64.
        libelf.elf_fill(0xcc)

    # --------------------------------------------------------------------------- #
    #  Copy executable header                                                     #
    # --------------------------------------------------------------------------- #
        # ELF class of input file
        elfclass: c_int = libelf.gelf_getclass(srce)
        if elfclass == ELFCLASSNONE.value:
            print_error("Could not retrieve ELF class from input file")
            raise cu

        # executable header of input file
        srcehdr = GElf_Ehdr()
        if libelf.gelf_getehdr(srce, pointer(srcehdr)) is None:
            print_error("Could not retrieve executable header from input file: " + libelf.elf_errmsg(c_int(-1)))
            raise cu

        #  gelf_newehdr sets automatically the magic numbers of an ELF header,
        #  the EI_CLASS byte according to elfclass, the EI_VERSION byte and
        #  e_version to the version you told the library to use.
        #
        #  The EI_DATA byte is set to ELFDATANONE, e_machine to EM_NONE and
        #  e_type to ELF_K_NONE.
        #
        #  Other members are set to zero. This includes the EI_OSABI and
        #  EI_ABIVERSION bytes.

        # executable header of output file
        dstehdr_pointer: POINTER(GElf_Ehdr) = libelf.gelf_newehdr(dste, elfclass)
        if dstehdr_pointer is None:
            print_error("Could not create executable header of output file: " + libelf.elf_errmsg(c_int(-1)))
            raise cu

        dstehdr: GElf_Ehdr = dstehdr_pointer.contents
        dstehdr.e_ident[EI_DATA] = srcehdr.e_ident[EI_DATA]
        dstehdr.e_ident[EI_OSABI] = srcehdr.e_ident[EI_OSABI]
        dstehdr.e_ident[EI_ABIVERSION] = srcehdr.e_ident[EI_ABIVERSION]
        dstehdr.e_machine = srcehdr.e_machine
        dstehdr.e_type = srcehdr.e_type
        dstehdr.e_flags = srcehdr.e_flags
        dstehdr.e_shstrndx = srcehdr.e_shstrndx
        dstehdr.e_entry = srcehdr.e_entry

        if libelf.gelf_update_ehdr(dste, dstehdr_pointer) == 0:
            print_error("Could not update ELF structures (Header): " + libelf.elf_errmsg(c_int(-1)))
            raise cu

    # --------------------------------------------------------------------------- #
    #  Copy program headers                                                       #
    # --------------------------------------------------------------------------- #
        # number of sections in input file
        scnnum: c_size_t[int] = c_size_t(0)
        if libelf.elf_getshdrnum(srce, pointer(scnnum)) != 0:
            print_error("Could not retrieve number of sections from input file: " + libelf.elf_errmsg(c_int(-1)))
            raise cu

        section_ranges: List[List[FileFragment]] = computeSectionRanges(srce, ranges, scnnum)

        # number of segments in input file
        phdrnum: c_size_t[int] = c_size_t(0)
        if libelf.elf_getphdrnum(srce, byref(phdrnum)) != 0:
            print_error("Could not retrieve number of segments from input file: " + libelf.elf_errmsg(c_int(-1)))
            raise cu

        # number of LOAD segments in source file
        loads: int = countLOADs(srce)
        # description of layout of output file
        # TODO: loadable von unloadable Segmenten trennen
        desc: LayoutDescription = calculateNewFilelayout(section_ranges, scnnum.value, phdrnum.value - loads, elfclass, args.permutate)
        dstehdr.e_phoff = desc.phdr_start
        # PHDR table of output file
        dstphdrs: POINTER(GElf_Phdr) = libelf.gelf_newphdr(dste, desc.phdr_entries)
        if dstphdrs is None:
            print_error("Could not create PHDR table for output file: " + libelf.elf_errmsg(c_int(-1)))
            raise cu

        # XXX: Debug
        print("descriptor", desc)

        # current PHDR entry of input file
        srcphdr = GElf_Phdr()
        # index of current PHDR entry in output file
        new_index: int = 0
        # flag if the current LOAD segment is the first of the input file
        first_load: bool = True
        # construct new PHDR table from old PHDR table
        for i in range(0, phdrnum.value):
            if libelf.gelf_getphdr(srce, c_int(i), byref(srcphdr)) is None:
                print_error("Could not retrieve phdr structure {0} of input file: {1}".format(i, libelf.elf_errmsg(c_int(-1))))
                raise cu

            if srcphdr.p_type != PT_LOAD:
                # copy values of non-LOAD segments - addresses and offsets will
                # be fixed later
                dstphdrs[new_index].p_type = srcphdr.p_type
                dstphdrs[new_index].p_offset = srcphdr.p_offset
                dstphdrs[new_index].p_vaddr = srcphdr.p_vaddr
                dstphdrs[new_index].p_paddr = srcphdr.p_paddr
                dstphdrs[new_index].p_filesz = srcphdr.p_filesz
                dstphdrs[new_index].p_memsz = srcphdr.p_memsz
                dstphdrs[new_index].p_flags = srcphdr.p_flags
                dstphdrs[new_index].p_align = srcphdr.p_align
                new_index += 1
            elif first_load:
                # replace first LOAD segment of input file with all LOAD segments
                # of output file
                first_load = False

                tmp: FragmentRange
                # TODO: loadable_segmentList existiert noch nicht
                for tmp in desc["loadable_segmentList"]:
                    dstphdrs[new_index].p_type = PT_LOAD
                    dstphdrs[new_index].p_offset = tmp.offset + tmp.shift
                    dstphdrs[new_index].p_vaddr = tmp.vaddr
                    dstphdrs[new_index].p_paddr = tmp.vaddr
                    dstphdrs[new_index].p_filesz = tmp.fsize
                    dstphdrs[new_index].p_memsz = tmp.msize
                    dstphdrs[new_index].p_flags = tmp.flags
                    dstphdrs[new_index].p_align = PAGESIZE
                    new_index += 1
            else:
                # skip all other LOAD segments
                continue

        # fix up non-LOAD segments
        for i in range(0, desc.phdr_entries):
            if dstphdrs[i].p_type != PT_LOAD:
                for tmp in desc.segment_list:
                    if tmp.vaddr <= dstphdrs[i].p_vaddr and dstphdrs[i].p_vaddr + dstphdrs[i].p_filesz <= tmp.vaddr + tmp.fsize:
                        dstphdrs[i].p_offset = tmp.offset + (dstphdrs[i].p_vaddr - tmp.vaddr)
                        break

                if dstphdrs[i].p_type == PT_PHDR:
                    # fix up PHDR segment
                    dstphdrs[i].p_vaddr = desc.phdr_vaddr
                    dstphdrs[i].p_paddr = dstphdrs[i].p_vaddr
                    dstphdrs[i].p_offset = desc.phdr_start
                    if elfclass == ELFCLASS32:
                        dstphdrs[i].p_filesz = desc.phdr_entries * sizeof_elf32_phdr
                    else:
                        dstphdrs[i].p_filesz = desc.phdr_entries * sizeof_elf64_phdr

                    dstphdrs[i].p_memsz = dstphdrs[i].p_filesz

    # --------------------------------------------------------------------------- #
    # Copy sections and section headers                                           #
    # --------------------------------------------------------------------------- #
        # current section header of input file
        srcshdr = GElf_Shdr()
        # current section header of output file
        dstshdr = GElf_Shdr()
        # lib creates section 0 automatically so we start with section 1
        for i in range(1, scnnum.value):
            srcscn: c_void_p = libelf.elf_getscn(srce, c_int(i))
            if srcscn is None:
                print_error("Could not retrieve section {0} of input file: {1}".format(i, libelf.elf_errmsg(c_int(-1))))
                raise cu

            if libelf.gelf_getshdr(srcscn, byref(srcshdr)) is None:
                print_error("Could not retrieve shdr structure for section {0} of input file: {1}".format(i, libelf.elf_errmsg(c_int(-1))))
                raise cu

            dstscn: c_void_p = libelf.elf_newscn(dste)
            if dstscn is None:
                print_error("Could not create section {0} in output file: {1}".format(i, libelf.elf_errmsg(c_int(-1))))
                raise cu

            if libelf.gelf_getshdr(dstscn, byref(dstshdr)) is None:
                print_error("Could not retrieve shdr structure for section {0} of output file: {1}".format(i, libelf.elf_errmsg(c_int(-1))))
                raise cu

##########################################################################################
            # TODO: buffer bereitstellen
            # / *allocate buffers for the data of the output file * /
            # for (Chain * tmp = & section_ranges[i]; tmp; tmp = tmp->next) {
            #   errno = 0;
            #   tmp->data.buffer = calloc(tmp->data.to - tmp->data.from, sizeof(char));
            #   if (tmp->data.buffer == NULL) {
            #       error(0, errno, "Out of memory");
            #       goto err_free_dstshdr;
            #   }
            # }
            ###################################################################################

            # current data of current section of input file
            srcdata_pointer: POINTER(Elf_Data) = libelf.elf_getdata(srcscn, None)
            # copy data in data buffers for output file
            while srcdata_pointer is not None:
                srcdata = srcdata_pointer.contents
                if srcdata.d_buf is None:
                    # section is NOBITS section => no data to copy
                    continue

                srcdata_begin = srcdata.d_off
                srcdata_end = srcdata.d_off + srcdata.d_size
                for item_01 in section_ranges[i]:
                    if item_01.end <= srcdata_begin:
                        # source data begins after range ends
                        continue

                    if srcdata_end <= item_01.start:
                        # source data ends before range ( and the following range
                        # because the list is sorted) begins
                        break

                    if item_01.start <= srcdata_begin:
                        # range starts before source data starts
                        srcstart = 0
                        dststart = srcdata_begin - item_01.start
                    else:
                        # range starts after source data starts
                        srcstart = item_01.start - srcdata_begin
                        dststart = 0

                    if item_01.end >= srcdata_end:
                        # range ends after source data ends
                        srcend = srcdata_end
                    else:
                        # range ends before source data ends
                        srcend = item_01.end

                    # TODO: Daten übertragen
                    memcpy(item_01.buffer + dststart, srcdata.d_buf + srcstart, srcend - srcstart)
                    item_01.d_version = srcdata.d_version
                    item_01.d_type = srcdata.d_type

                srcdata_pointer = libelf.elf_getdata(srcscn, srcdata_pointer)

            # construct data descriptors of current section
            for item_02 in section_ranges[i]:
                dstdata = libelf.elf_newdata(dstscn)
                if dstdata is None:
                    print_error("Could not add data to section {0} of output file: {1}".format(i, libelf.elf_errmsg(c_int(-1))))
                    raise cu

                # alignment does not matter here because the position of the data range is controlled via d_off
                dstdata.d_align = 1
                dstdata.d_type = item_02.d_type
                dstdata.d_version = item_02.d_version
                dstdata.d_buf = item_02.buffer
                dstdata.d_off = item_02.start + item_02.fragment_shift
                dstdata.d_size = item_02.end - item_02.start

            # construct the SHDR entry of current section
            dstshdr.sh_info = srcshdr.sh_info
            dstshdr.sh_name = srcshdr.sh_name
            dstshdr.sh_type = srcshdr.sh_type
            dstshdr.sh_addr = srcshdr.sh_addr
            dstshdr.sh_flags = srcshdr.sh_flags
            dstshdr.sh_addralign = srcshdr.sh_addralign
            dstshdr.sh_offset = srcshdr.sh_offset + section_ranges[i][0].section_shift
            if srcshdr.sh_type == SHT_NOBITS:
                dstshdr.sh_size = srcshdr.sh_size
            else:
                dstshdr.sh_size = calculateSectionSize(section_ranges[i])
            dstshdr.sh_entsize = srcshdr.sh_entsize
            dstshdr.sh_link = srcshdr.sh_link

            if libelf.gelf_update_shdr(dstscn, dstshdr) == 0:
                print_error("Could not update ELF structures (Sections): " + libelf.elf_errmsg(c_int(-1)))
                raise cu

        dstehdr.e_shoff = desc.shdr_start

        # TODO: libelf Funktionen
        # write new ELF file
        if libelf.elf_update(dste, ELF_C_WRITE) == -1:
            print_error("Could not write ELF structures to output file: " + libelf.elf_errmsg(c_int(-1)))
            raise cu
    except CleanUp:
        cu.exitstatus = 1
    # XXX: Debug
    # except Exception as e:
    #     cu.exitstatus = 1
    #     print(e.args)
    finally:
        if cu.level >= 4:
            libelf.elf_end(dste)
        if cu.level >= 3:
            os.close(dstfd)
        if cu.level >= 2:
            libelf.elf_end(srce)
        if cu.level >= 1:
            os.close(srcfd)
        print(cu.level, cu.exitstatus)


# FIXME: Doku
if __name__ == "__main__":
    # --------------------------------------------------------------------------- #
    #  Command line argument processing                                           #
    # --------------------------------------------------------------------------- #
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("file", help="the file, which should be shrunk")
    parser.add_argument("-k", "--keep", metavar="RANGE", action='append', help="Keep given %(metavar)s in new file. Accepted formats are\n 'START-END'   exclusive END\n 'START:LEN'   LEN in bytes\nwith common prefixes for base")
    parser.add_argument("-K", "--keep-file", metavar="FILE", help="File to read ranges from")
    parser.add_argument("-p", "--permute", action='store_true', help="Permute fragments for potential smaller output file.\nWARNING: The used algorithm is in O(n!)")
    parser.add_argument("-o", "--output-file", metavar="FILE", help="Name of the output file")
    args = parser.parse_args()

    # parse ranges to keep
    if args.keep is None:
        if args.keep_file is None:
            print_error("No ranges specified. Aborting!")
            exit(1)
        else:
            args.keep = []
            for line in open(args.keep_file):
                args.keep.append(line)

    ranges: List[(int, int)] = []
    error = False
    for item in args.keep:
        if ":" in item:
            frag_desc = item.split(":")
            if len(frag_desc) != 2:
                print_error("Invalid range argument '" + item + "' - ignoring!")
                error = True
                continue

            try:
                start = int(frag_desc[0], base=0)
            except ValueError:
                print_error("First part ('" + frag_desc[0] + "') of range argument '" + item + "' not parsable - ignoring!")
                error = True
                continue

            try:
                length = int(frag_desc[1], base=0)
            except ValueError:
                print_error("Second part ('" + frag_desc[1] + "') of range argument '" + item + "' not parsable - ignoring!")
                error = True
                continue

            if start < 0:
                print_error("START of " + item + "must be bigger than or equal to zero (is " + str(start) + ") - ignoring!")
                error = True
                continue
            if length < 1:
                print_error("LEN of " + item + "must be bigger than zero (is " + str(length) + ") - ignoring!")
                error = True
                continue

            tmp = insertTuple((start, start + length), ranges)
            if tmp is not None:
                print_error(item + "overlaps with" + tmp)
                error = True
                continue
        elif "-" in item:
            frag_desc = item.split("-")
            if len(frag_desc) != 2:
                print_error("Invalid range argument '" + item + "' - ignoring!")
                error = True
                continue

            try:
                start = int(frag_desc[0], base=0)
            except ValueError:
                print_error("First part ('" + frag_desc[0] + "') of range argument '" + item + "' not parsable - ignoring!")
                error = True
                continue

            try:
                end = int(frag_desc[1], base=0)
            except ValueError:
                print_error("Second part ('" + frag_desc[1] + "') of range argument '" + item + "' not parsable - ignoring!")
                error = True
                continue

            if start < 0:
                print_error("START of " + item + "must be bigger than or equal to zero (is " + str(start) + ") - ignoring!")
                error = True
                continue
            if end <= start:
                print_error("END of " + item + "must be bigger than START (START: " + str(start) + ", END: " + str(end) + ") - ignoring!")
                error = True
                continue

            tmp = insertTuple((start, end), ranges)
            if tmp is not None:
                print_error(item + "overlaps with" + tmp)
                error = True
                continue
        else:
            print_error("Invalid range argument '{0}' - ignoring!".format(item))
            error = True
            continue

    if len(ranges) == 0:
        print_error("No valid ranges! Aborting")
        exit(1)

    if error:
        decision = input("Errors during argument parsing detected. Abort? (Y/n): ")
        while decision != "Y" and decision != "n":
            decision = input("Please enter (Y/n): ")
        if decision == "Y":
            exit(1)

    # determine output file name
    if args.output_file is not None:
        # user specified output file name
        if args.output_file == args.file:
            print_error("Input and output file are the same! Aborting")
            exit(1)
    else:
        # generate own output file name
        args.output_file = args.file + FILESUFFIX

    # XXX: Debug
    print(ranges)
    shrinkelf(args, ranges)
    exit(cu.exitstatus)
