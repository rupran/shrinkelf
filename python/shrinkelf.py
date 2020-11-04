#!/usr/bin/python3

from ctypes import *

import argparse
from sys import stderr
import os


from elfdefinitions import *



# \brief File suffix for output file appended to the input file when no output
#        file was specified */
FILESUFFIX = ".shrinked"



class CleanUp(Exception):
    def __init__(self, level, exitstatus):
        self.level = level
        self.exitstatus = exitstatus

cu = CleanUp(0, 0)



def print_error(text):
    print(text, file=stderr)



# Inserts element `item` in sorted list of ranges and returns `None` on
# success. On failure returns the range `item` overlaps with and does NOT
# insert `item` in list
def insertTuple(item, list_of_items):
    length = len(list_of_items)
    if length == 0:
        list_of_items.append(item)
        return None
    else:
        for i in range(0, length):
            tmp = list_of_items[i]
            if item[1] < tmp[0]:
                # item must be sorted in before current element
                list_of_items.insert(i, item)
                return None
            elif item[0] <= tmp[1]:
                # item overlaps with current element
                return tmp
        list_of_items.append(item)
        return None



# Inserts element `item` in sorted list of ranges and returns `None` on
# success. On failure returns the range `item` overlaps with and does NOT
# insert `item` in list
def insertRange(item, list_of_items):
    length = len(list_of_items)
    if length == 0:
        list_of_items.append(item)
        return None
    else:
        for i in range(0, length):
            tmp = list_of_items[i]
            if item["data"]["to"] < tmp["data"]["from"]:
                # item must be sorted in before current element
                list_of_items.insert(i, item)
                return None
            elif item["data"]["from"] <= tmp["data"]["to"]:
                # item overlaps with current element
                return tmp
        list_of_items.append(item)
        return None



# \brief Counts LOAD program headers in an ELF file
#
# \param elf The file
#
# \returns The number of LOAD program headers
def countLOADs(elf):
    count = 0

    # number of segments in file
    phdrnum = c_size_t(0)
    if libelf.elf_getphdrnum(elf, byref(phdrnum)) != 0:
        print_error("Could not retrieve number of segments from source file: ", libelf.elf_errmsg(c_int(-1)))
        raise cu

    phdr = GElf_Phdr()
    for i in range(0, phdrnum):
        if libelf.gelf_getphdr(elf, i, byref(phdr)) == None:
            print_error("Could not retrieve source phdr structure {0}: {1}".format(i, libelf.elf_errmsg(c_int(-1))))
            raise cu

        if phdr.p_type == PT_LOAD:
            count += 1

    return count



# \brief Constructs the [address ranges](@ref segmentRange) of a section
#
# \param section List of [data ranges](@ref range) of a section
# \param section_start Start address of this section in the new file
#
# \return A list of [address ranges](@ref segmentRange) fit for rearrangement
#         or `None` in case of an error
def segments(section, section_start):
    if section == None or len(section) == 0:
        # XXX: Debug
        print("segments: section was none")
        return None

    ret = []

    current = {}
    current["offset"] = section[0]["data"]["section_offset"] + section[0]["data"]["from"]
    current["fsize"] = section[0]["data"]["to"] - section[0]["data"]["from"]
    current["vaddr"] = section[0]["as"]["from"]
    current["msize"] = section[0]["as"]["to"] - section[0]["as"]["from"]
    current["flags"] = section[0]["as"]["flags"]
    current["loadable"] = section[0]["as"]["loadable"];
    current["section_start"] = section_start
    for i in range(1, len(section)):
        if ((current["vaddr"] + current["msize"]) / PAGESIZE) == (section[i]["as"]["from"] / PAGESIZE):
            # data of tmp range will be loaded in the same page as content of
            # current range => merge the ranges
            current["fsize"] = section[i]["data"]["section_offset"] + section[i]["data"]["to"] - current["offset"]
            current["msize"] = section[i]["as"]["to"] - current["vaddr"]
            current["loadable"] |= section[i]["as"]["loadable"]
            current["flags"] |= tmp["as"]["flags"]
        else:
            # data of tmp range will not be loaded in the same page as content
            # of current range => create new range
            ret.append(current)
            current = {}

            current["range"]["offset"] = section[i]["data"]["section_offset"] + section[i]["data"]["from"]
            current["range"]["fsize"] = section[i]["data"]["to"] - section[i]["data"]["from"]
            current["range"]["vaddr"] = section[i]["as"]["from"]
            current["range"]["msize"] = section[i]["as"]["to"] - section[i]["as"]["from"]
            current["range"]["flags"] = section[i]["as"]["flags"]
            current["range"]["loadable"] = section[i]["as"]["loadable"]
            current["range"]["section_start"] = section_start

    ret.append(current)
    # XXX: Debug
    print(ret)
    return ret



# \brief Counts the loadable [address ranges](@ref segmentRange) in a list
#
# \param segmentList The list
#
# \return Number of loadable [address ranges](@ref segmentRange)
#/
def countLoadableSegmentRanges(segmentList):
    ret = 0
    for item in segmentList:
        if item["range"]["loadable"]:
            ret += 1

    return ret



# \brief Constructor for ::permutation
#
# \param segments List of lists of [address ranges](@ref segmentRange)
#                 imposing constraints on the permutation
# \param index The index for which a ::permutation is constructed
# \param current_size The currently occupied size in the new file
#
# \return The new ::permutation
def createPermutation(segments, index, current_size):
    ret = {}
    ret["numEntries"] = len(segments[index])
    ret["tmp"] = [int] * ret["numEntries"]
    ret["result"] = [int] * ret["numEntries"]

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
    # concecptionally - to infinity because it is not determined now
    # TODO: ggf. Vergleiche anpassen
    ret["size"] = -1

    return ret



# FIXME:
# \brief Calculates offset of a section in new file.
#
# Contraint: new offset needs to be equal to prior offset modulo page size
# because LOAD segments require that `p_offset` (offset in file) is equal to
# `p_vaddr` (address in virtual address space) modulo page size.
#
# \param priorOffset Offset of section in original file
# \param occupiedSpace Number of already occupied bytes in new file
#
# \return Offset in new file
def calculateOffset(size_t priorOffset, size_t occupiedSpace) {
    priorPageOffset = priorOffset % PAGESIZE
    occupiedPageOffset = occupiedSpace % PAGESIZE
    if occupiedPageOffset <= priorPageOffset:
        return occupiedSpace - occupiedPageOffset + priorPageOffset
    else:
        return occupiedSpace - occupiedPageOffset + priorPageOffset + PAGESIZE



# FIXME
# \brief Evaluates the current permutation of address ranges
#
# Computes the size of the section if the address ranges it contains are
# inserted in the ordering dscribed by the current permutation. Updates the
# currantly best permutation and its resulting size if needed.
#
# \param perm The [state of the permutation algorithm](@ref permutation)
#             containing the current and the best permutation
# \param segments The address ranges to insert
#/
def evaluate(struct permutation *perm, struct segmentRanges *segments) {
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



# FIXME:
# \brief recursive backtracking algorithm for permutation of [address ranges]
# (@ref segmentRange)
#
# \param perm The state of the algorithm
# \param segments The address ranges to permutate
# \param index The current position where a address range is inserted (doubles
#              as depth of recursion)
def recursive_permutate(struct permutation *perm, struct segmentRanges *segments, unsigned long long index) {
    if index > perm["numEntries"]:
        # all address ranges are inserted
        evaluate(perm, segments)
        return

    if index == 1 and perm["tmp"][0] == -1:
        # first address range is constrained by the first element of segments
        recursive_permutate(perm, segments, index + 1)
    elif index == perm["numEntries"] and perm["tmp"][-1] == -1:
        # last address range is constrained by the last element of segments
        recursive_permutate(perm, segments, index + 1)
    else:
        for i in range(0, perm["numEntries"]):
            # check if range is not inserted yet
            if perm["tmp"][i] == 0:
                # insert range temporary
                perm["tmp"][i] = index
                # try every possible permutation with the remaining ranges
                recursive_permutate(perm, segments, index + 1)
                # remove range to try the next for this position
                perm["tmp"][i] = 0



# FIXME:
# \brief Computes the offset of the address ranges in the output file
#
# \param perm The order in which the ranges are inserted
# \param segments The ranges that are inserted
# \param current_size The already occupied size in the output file
def segmentOffsets(struct permutation *perm, struct segmentRanges *segments, unsigned long long current_size) {
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



# FIXME:
# \brief Permutates the address ranges for all sections
#
# \param segments Array of list of address ranges
# \param size Size of `segments`
# \param current_size The currently occupied space in the output file
#
# \return The size of the output file after inserting all address ranges
#/
def permutate(struct segmentRanges **segments, size_t size, unsigned long long current_size) {
    for i in range(1, size):
        perm = createPermutation(segments, size, i, current_size)
        # permutate the address ranges of section i
        recursive_permutate(perm, segments[i], 1);
        # calculate the offsets of the address ranges of section i
        segmentOffsets(perm, segments[i], current_size)
        # update current size
        current_size = segments[i]["section_start"] + perm["size"]

    return current_size



# FIXME
# \brief Rounds up `value` to the next multiple of `base`
#
# Computes a value `x` such that `x % base == 0`, `x >= value` and `x` is minimal.
#
# \param value The value for which the next bigger multiple is computed
# \param base The value of which the multiple is computed
#
# \returns The multiple of base
#/
def roundUp(value, base):
    tmp = value % base
    if tmp != 0:
        return value - tmp + base
    else:
        return value



# FIXME
# \brief Checks if a [address range](@ref segmentRange) contains a [data range](@ref range)
#
# \param segment The address range
# \param range The data range
#
# \return Value indicating if the address range contains the data range
#/
def contains(struct segmentRanges * segment, Chain *range) {
    if range["data"]["section_offset"] + range["data"]["to"] <= segment["offset"] + segment["fsize"] and range["data"]["section_offset"] + range["data"]["from"] >= segment["offset"]:
        return True
    return False



# FIXME:
# \brief Computes the section and data shift of all [data ranges](@ref range)
#        from the shift of the [address range](@ref segmentRange)
#
# \param ranges Array of list of [data ranges](@ref range)
# \param segments Array of list of [address ranges](@ref segmentRange)
# \param size Size of these arrays
#/
def calculateShift(Chain *ranges, struct segmentRanges **segments, size_t size) {
    for i in range(1, size):
        for tmp in segments[i]:
            for tmpSec in ranges[i]:
                if contains(tmp, tmpSec):
                    tmpSec["data"]["section_shift"] = tmp["section_start"] - tmpSec["data"]["section_offset"]
                    tmpSec["data"]["data_shift"] = tmp["shift"] - tmpSec["data"]["section_shift"]


# FIXME:
def calculatePHDRInfo(fileoffset, memoryoffset, elfclass, addEHDR):
    if elfclass == ELFCLASS32:
        realfileoffset = fileoffset if !addEHDR else fileoffset + sizeof(Elf32_Ehdr)
        realmemoryoffset = memoryoffset if !addEHDR else memoryoffset + sizeof(Elf32_Ehdr)
        phdr_start = roundUp(realfileoffset, PHDR32ALIGN)
        phdr_vaddr = roundUp(realmemoryoffset, PHDR32ALIGN)
        entry_size = sizeof(Elf32_Phdr)
    else:
        realfileoffset = fileoffset if !addEHDR else fileoffset + sizeof(Elf64_Ehdr)
        realmemoryoffset = memoryoffset if !addEHDR else memoryoffset + sizeof(Elf64_Ehdr)
        phdr_start = roundUp(realfileoffset, PHDR64ALIGN)
        phdr_vaddr = roundUp(realmemoryoffset, PHDR64ALIGN)
        entry_size = sizeof(Elf64_Phdr)

    return (phdr_start, phdr_vaddr, entry_size)



# FIXME
def mergeFragments(fragments, startWithEHDR):
    ret = []
    current = {}
    if startWithEHDR:
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
        currentPage = (current["vaddr"] + current["msize"]) / PAGESIZE
        # FIXME
        # first memory page with content from the item range
        tmpPage = item["vaddr"] / PAGESIZE
        # last file page with content from the current range
        currentFilePage = (current["offset"] + current["fsize"]) / PAGESIZE
        # FIXME
        # first file page with content from the item range
        tmpFilePage = (item["offset"] + item["shift"]) / PAGESIZE

        if currentPage == tmpPage or (currentPage + 1 == tmpPage and currentFilePage + 1 == tmpFilePage):
            # FIXME
            # data of tmp range will be loaded in the same or the following
            # page as content of current range => merge the ranges
            current["fsize"] = item["offset"] + item["shift"] + item["fsize"] - current["offset"]
            current["msize"] = item["vaddr"] + item["msize"] - current["vaddr"]
            current["loadable"] |= item["loadable"]
            current["flags"] |= item["flags"]
        else:
            # FIXME
            # data of tmp range will be loaded in a page farther away from the
            # content of current range => create new ranges
            ret.append(current)
            current = {}
            current["offset"] = item["offset"] + item["shift"]
            current["fsize"] = item["fsize"]
            current["vaddr"] = item["vaddr"]
            current["msize"] = item["msize"]
            current["flags"] = item["flags"]
            current["loadable"] = item["loadable"]

    return ret
# \brief Calculates the new file layout
#
# FIXME:
# \param ranges Array of list of data rangesto incorporate in the new file
# \param size Size of ranges
# \param oldEntries Number of PHDR entries of original file that are NOT LOADs
# \param elfclass Elf Class (32bit or 64bit)
# \param permutateRanges Flag if the address ranges of sections should be permutated
#
# \return The [description of the file layout](@ref layoutDescription) of the
#         output file
#/
def calculateNewFilelayout(Chain *ranges, size_t size, size_t oldEntries, int elfclass, int permutateRanges) {
    ret = {}
    ret["segmentNum"] = size;

    # number of LOAD entries in new PHDR table
    # Start with one for file header and one for PHDR table
    loads = 2
    current_size = 0
    if elfclass == ELFCLASS32:
        current_size = sizeof(Elf32_Ehdr)
    else:
        current_size = sizeof(Elf64_Ehdr)

    segments = [[]] * size
    # ignore section 0 (that is not a "real" section)
    for i in (1, size):
        # determine the address ranges from the data ranges of a section
        segments[i] = segments(ranges[i], ranges[i][0]["data"]["section_offset"])
        loads += countLoadableSegmentRanges(segments[i])

    ret["segments"] = segments

    # check if user want to permutate address ranges
    if permutateRanges:
        current_size = permutate(ret["segments"], ret["segmentNum"], current_size)
        if current_size == 0:
            raise cu
    else:
        # simply push the address ranges together
        for i in range(1, size):
            section_start = calculateOffset(ret["segments"][i]["section_start"], current_size)
            for item in ret["segments"][i]:
                item["shift"] = calculateOffset(item["offset"], current_size) - item["offset"]
                item["section_start"] = section_start
                current_size = calculateOffset(item["offset"], current_size) + item["fsize"]

    # join address ranges between sections
    ret["listEntries"] = loads + oldEntries
    ret["segmentList"] = []
    current = {}
    current["offset"] = 0
    current["fsize"] = ret["segments"][1]["offset"] + ret["segments"][1]["shift"] + ret["segments"][1]["fsize"]
    current["vaddr"] = (ret["segments"][1]["vaddr"] / PAGESIZE) * PAGESIZE
    current["msize"] = current["fsize"]
    current["flags"] = ret["segments"][1]["flags"]
    current["loadable"] = True
    ret["listEntries"] -= 1
    for i in range(1, len(ret["segments"][1])):
        tmp = ret["segments"][1][i]

        # last memory page with content from the current range
        currentPage = (current["vaddr"] + current["msize"]) / PAGESIZE
        # first memory page with content from the tmp range
        tmpPage = tmp["vaddr"] / PAGESIZE
        # last file page with content from the current range
        currentFilePage = (current["offset"] + current["fsize"]) / PAGESIZE
        # first file page with content from the tmp range
        tmpFilePage = (tmp["offset"] + tmp["shift"]) / PAGESIZE

        if currentPage == tmpPage or (currentPage + 1 == tmpPage and currentFilePage + 1 == tmpFilePage):
            # data of tmp range will be loaded in the same or the following
            # page as content of current range => merge the ranges
            current["fsize"] = tmp["offset"] + tmp["shift"] + tmp["fsize"] - current["offset"]
            current["msize"] = tmp["vaddr"] + tmp["msize"] - current["vaddr"]
            current["loadable"] |= tmp["loadable"]
            current["flags"] |= tmp["flags"]
            ret["listEntries"] -= 1
        else:
            # data of tmp range will be loaded in a page farther away from the
            # content of current range => create new ranges
            ret["segmentList"].append(current)
            current = {}
            current["offset"] = tmp["offset"] + tmp["shift"]
            current["fsize"] = tmp["fsize"]
            current["vaddr"] = tmp["vaddr"]
            current["msize"] = tmp["msize"]
            current["flags"] = tmp["flags"]
            current["loadable"] = tmp["loadable"]
    for i in range(2, size):
        for tmp in ret["segments"][i]:
            # last memory page with content from the current range
            currentPage = (current["vaddr"] + current["msize"]) / PAGESIZE
            # first memory page with content from the tmp range
            tmpPage = tmp["vaddr"] / PAGESIZE
            # last file page with content from the current range
            currentFilePage = (current["offset"] + current["fsize"]) / PAGESIZE
            # first file page with content from the tmp range
            tmpFilePage = (tmp["offset"] + tmp["shift"]) / PAGESIZE

            if currentPage == tmpPage or (currentPage + 1 == tmpPage and currentFilePage + 1 == tmpFilePage):
                # data of tmp range will be loaded in the same or the following
                # page as content of current range => merge the ranges
                current["fsize"] = tmp["offset"] + tmp["shift"] + tmp["fsize"] - current["offset"]
                current["msize"] = tmp["vaddr"] + tmp["msize"] - current["vaddr"]
                current["loadable"] |= tmp["loadable"]
                current["flags"] |= tmp["flags"]
                ret["listEntries"] -= 1
            else:
                # data of tmp range will be loaded in a page farther away from
                # the content of current range => create new ranges
                ret["segmentList"].append(current)
                current = {}
                current["offset"] = tmp["offset"] + tmp["shift"]
                current["fsize"] = tmp["fsize"]
                current["vaddr"] = tmp["vaddr"]
                current["msize"] = tmp["msize"]
                current["flags"] = tmp["flags"]
                current["loadable"] = tmp["loadable"]

    # insert PHDR table
    current = ret["segmentList"][0]
    for i in range(0, size):
        entry_size = 0
        phdr_vaddr = 0
        phdr_start = 0
        # determine which start addresses the PHDR table would have if it were
        # inserted after section i (i == 0 meaning inserting after file header)
        if i == 0:
            phdr_start, phdr_vaddr, entry_size = calculatePHDRInfo(0, current["vaddr"], elfclass, True)
        else:
            tmp = ret["segments"][i][-1]
            fileoffset = tmp["offset"] + tmp["fsize"] + tmp["shift"]
            memoryoffset = tmp["vaddr"] + tmp["msize"]
            phdr_start, phdr_vaddr, entry_size = calculatePHDRInfo(fileoffset, memoryoffset, elfclass, False)

        # check if PHDR table fits in the space in memory after section i
        if i == size - 1:
            # insert after all sections
            # XXX: untested
            # FIXME: Aligment not given after NOBITS sections
            ret["phdr_start"] = phdr_start
            ret["phdr_vaddr"] = phdr_vaddr
            ret["phdr_entries"] = ret["listEntries"]
            table_size = entry_size * ret["phdr_entries"]
            current_size = ret["phdr_start"] + table_size
            # TODO: Sprungmarke fixen
            goto done;
        else:
            # TODO:
	    while (phdr_vaddr >= current->next->range.vaddr) {
	    	current = current->next;
	    }

            if phdr_vaddr < current["vaddr"] + current["msize"]:
                ahead = ret["segments"][i + 1][0]
                if ahead["vaddr"] >= phdr_vaddr + entry_size * ret["listEntries"]:
                    ret["phdr_start"] = phdr_start
                    ret["phdr_vaddr"] = phdr_vaddr
                    ret["phdr_entries"] = ret["listEntries"]
                    if ahead["offset"] + ahead["shift"] < ret["phdr_start"] + ret["phdr_entries"] * entry_size:
                        shift = roundUp(ret["phdr_start"] + ret["phdr_entries"] * entry_size - (ahead["offset"] + ahead["shift"]), PAGESIZE)
                        for j in range(i + 1, size):
                            for tmp3 in ret["segments"][j]:
                                tmp3["shift"] += shift
                                tmp3["section_start"] += shift
                        current_size += shift
                        # correct offset of LOAD PHDRs after inserting PHDR table
                        current["fsize"] += shift
                        # TODO:
		    	for (struct segmentRanges *tmp4 = current->next; tmp4; tmp4 = tmp4->next) {
		    		tmp4->range.offset += shift;
		    	}

                    # TODO:
		    if (current->next) {
                        # last memory page with content from the current range
                        currentPage = (current["vaddr"] + current["msize"]) / PAGESIZE
                        # first memory page with content from the next range
                        # TODO:
		    	unsigned long long tmpPage = current->next->range.vaddr / PAGESIZE;
                        # last file page with content from the current range
                        currentFilePage = (current["offset"] + current["fsize"]) / PAGESIZE
                        # first file page with content from the next range
                        # TODO:
		    	unsigned long long tmpFilePage = (current->next->range.offset + current->next->range.shift) / PAGESIZE;
                        if currentPage + 1 == tmpPage and currentFilePage + 1 == tmpFilePage:
                            # data of next range will be loaded in the
                            # following page as content of current range =>
                            # merge the ranges
                            # TODO:
		    	    current->range.fsize = current->next->range.offset + current->next->range.shift + current->next->range.fsize - current->range.offset;
		    	    current->range.msize = current->next->range.vaddr + current->next->range.msize - current->range.vaddr;
		    	    current->range.loadable |= current->next->range.loadable;
		    	    current->range.flags |= current->next->range.flags;
                            ret["listEntries"] -= 1
                            ret["phdr_entries"] -= 1
                            # TODO:
		    	    current->next = current->next->next;
                    # TODO: Sprungmarke fixen
                    goto done;
            else:
                fits = True
                for ahead in ret["segments"][i + 1]:
                    if ahead["vaddr"] < phdr_vaddr + entry_size * ret["listEntries"]:
                        fits = False
                if !fits:
                    continue
                ahead = ret["segments"][i + 1]
                ret["phdr_start"] = phdr_start
                ret["phdr_vaddr"] = phdr_vaddr
                ret["phdr_entries"] = ret["listEntries"]
                if ahead["offset"] + ahead["shift"] < ret["phdr_start"] + ret["phdr_entries"] * entry_size:
                    shift = roundUp(ret["phdr_start"] + ret["phdr_entries"] * entry_size - (ahead["offset"] + ahead["shift"]), PAGESIZE)
                    for j in range(i + 1, size):
                        for tmp3 in ret["segments"][j]:
                            tmp3["shift"] += shift
                            tmp3["section_start"] += shift
                    current_size += shift
                    # correct offset of LOAD PHDRs after inserting PHDR table
                    current["fsize"] += shift
                    # TODO:
		    for (struct segmentRanges *tmp4 = current->next; tmp4; tmp4 = tmp4->next) {
		    	tmp4->range.offset += shift;
		    }
                current["fsize"] = ret["phdr_start"] + ret["phdr_entries"] * entry_size - current["offset"]
                current["msize"] = ret["phdr_vaddr"] + ret["phdr_entries"] * entry_size - current["vaddr"];
                # TODO:
		if (current->next) {
                    # last memory page with content from the current range
                    currentPage = (current["vaddr"] + current["msize"]) / PAGESIZE
                    # first memory page with content from the next range
                    # TODO:
		    unsigned long long tmpPage = current->next->range.vaddr / PAGESIZE;
                    # last file page with content from the current range
                    currentFilePage = (current["offset"] + current["fsize"]) / PAGESIZE
                    # first file page with content from the next range
                    # TODO:
		    unsigned long long tmpFilePage = (current->next->range.offset + current->next->range.shift) / PAGESIZE;
                    if currentPage + 1 == tmpPage and currentFilePage + 1 == tmpFilePage:
                        # data of next range will be loaded in the following
                        # page as content of current range => merge the ranges
                        # TODO:
		    	current->range.fsize = current->next->range.offset + current->next->range.shift + current->next->range.fsize - current->range.offset;
		    	current->range.msize = current->next->range.vaddr + current->next->range.msize - current->range.vaddr;
		    	current->range.loadable |= current->next->range.loadable;
		    	current->range.flags |= current->next->range.flags;
                        ret["listEntries"] -= 1
                        ret["phdr_entries"] -= 1
                        # TODO:
		    	current->next = current->next->next;
                # TODO:
                goto done;

# TODO:
done:
    calculateShift(ranges, ret["segments"], size)

    # determine start of SHDR table
    if elfclass == ELFCLASS32:
        ret["shdr_start"] = roundUp(current_size, SHDR32ALIGN)
    else:
        ret["shdr_start"] = roundUp(current_size, SHDR64ALIGN)
    return ret



# \brief Computes the ranges to keep per section
#
# \param src Original ELF file to get data about sections
# \param ranges Ranges specified via command line
# \param section_number Number of sections in `src`
#
# \return a List of lists containing the ranges (with additional information)
#         per section
def computeSectionRanges(src, ranges, section_number):
    # number of segments in source file
    phdrnum = c_size_t(0)
    if libelf.elf_getphdrnum(src, byref(phdrnum)) != 0:
        print_error("Could not retrieve number of segments from source file: ", libelf.elf_errmsg(c_int(-1)))
        raise cu

    # current range to process
    r = 0
    # ranges split per section
    section_ranges = [None] * section_number.value
    for i in range(0, section_number.value):
        section_ranges[i] = []

        srcscn = libelf.elf_getscn(src, c_int(i))
        if srcscn == None:
            print_error("Could not retrieve source section data for section {0}: {1}".format(i, libelf.elf_errmsg(c_int(-1))))
            raise cu

        srcshdr = GElf_Shdr()
        if libelf.gelf_getshdr(srcscn, byref(srcshdr)) == None:
            print_error("Could not retrieve source shdr data for section {0}: {1}".format(i, elf_errmsg(c_int(-1))))
            raise cu

        # split ranges in section ranges and add layout data (ranges that end
        # in section i)
        while r < len(ranges) and ranges[r][1] <= srcshdr.sh_offset + (0 if srcshdr.sh_type == SHT_NOBITS else srcshdr.sh_size):
            tmp = {"data" : {}, "as" : {}}

            # determine start and end addresses of section range in file
            if srcshdr.sh_type == SHT_NOBITS:
                # NOBITS section don't have data in file
                tmp["data"]["from"] = 0
                tmp["data"]["to"] = 0
            else:
                # determine start of range under construction relativ to the
                # start of its containing section
                if ranges[r][0] < srcshdr.sh_offset:
                    # range under construction starts at the beginning of its
                    # containing section
                    tmp["data"]["from"] = 0
                else:
                    tmp["data"]["from"] = ranges[r][0] - srcshdr.sh_offset

                # determine end of range under construction relativ to the end
                # of its containing section
                if ranges[r][1] < srcshdr.sh_offset + srcshdr.sh_size:
                    tmp["data"]["to"] = ranges[r][1] - srcshdr.sh_offset
                else:
                    # range under construction ends at the end of its
                    # containing section
                    tmp["data"]["to"] = srcshdr.sh_size

                if srcshdr.sh_entsize != 0 and tmp["data"]["from"] % srcshdr.sh_entsize != 0:
                    print_error("In section {0}: range to keep is misaligned by {1} byte(s) (start relative to section start: 0x{2:x}, entrysize: 0x{3:x}, start of problematic range to keep: 0x{4:x})".format(i, tmp["data"]["from"] % srcshdr.sh_entsize, tmp["data"]["from"], srcshdr.sh_entsize, tmp["data"]["from"] + srcshdr.sh_offset))
                    raise cu

                if srcshdr.sh_entsize != 0 and tmp["data"]["to"] % srcshdr.sh_entsize != 0:
                    print_error("In section {0}: range to keep is misaligned by {1} byte(s) (end relative to section start: 0x{2:x}, entrysize: 0x{3:x}, end of problematic range to keep: 0x{4:x})".format(i, tmp["data"]["to"] % srcshdr.sh_entsize, tmp["data"]["to"], srcshdr.sh_entsize, tmp["data"]["to"] + srcshdr.sh_offset))
                    raise cu

            tmp["data"]["section_align"] = srcshdr.sh_addralign
            tmp["data"]["section_offset"] = srcshdr.sh_offset

            # memory layout of section range
            for j in range(0, phdrnum.value):
                srcphdr = GElf_Phdr()
                if libelf.gelf_getphdr(src, c_int(j), byref(srcphdr)) == None:
                    print_error("Could not retrieve source phdr structure {0}: {1}".format(i, libelf.elf_errmsg(c_int(-1))))
                    raise cu

                if srcphdr.p_type != PT_LOAD:
                    # not a loadable segment so it contains no data about the
                    # memory layout of any part of the input file
                    continue

                if srcphdr.p_offset >= srcshdr.sh_offset + (0 if srcshdr.sh_type == SHT_NOBITS else srcshdr.sh_size) or srcphdr.p_offset + (srcphdr.p_memsz if srcshdr.sh_type == SHT_NOBITS else srcphdr.p_filesz) <= srcshdr.sh_offset:
                    # loadable segment but does not load this section
                    continue

                tmp["as"]["loadable"] = True
                tmp["as"]["flags"] = srcphdr.p_flags
                tmp["as"]["align"] = srcphdr.p_align

                if srcshdr.sh_type == SHT_NOBITS:
                    # range contains whole NOBITS section
                    tmp["as"]["from"] = srcshdr.sh_addr
                    tmp["as"]["to"] = tmp["as"]["from"] + srcshdr.sh_size
                else:
                    # determine start and end addresses of section range in memory
                    if srcphdr.p_offset <= srcshdr.sh_offset:
                        # segment starts before section starts
                        tmp["as"]["from"] = srcphdr.p_vaddr + srcshdr.sh_offset + tmp["data"]["from"] - srcphdr.p_offset
                    else:
                        # segment starts after section starts
                        tmp["as"]["from"] = srcphdr.p_offset - srcshdr.sh_offset

                    tmp["as"]["to"] = tmp["as"]["from"] + (tmp["data"]["to"] - tmp["data"]["from"])

                break

            insertRange(tmp, section_ranges[i])
            r += 1

        # split ranges in section ranges and add layout data (range that begins
        # in section i but does not end there)
        if r < len(ranges) and ranges[r][0] < srcshdr.sh_offset + (0 if srcshdr.sh_type == SHT_NOBITS else srcshdr.sh_size):
            tmp = {"data" : {}, "as" : {}}

            # determine start and end addresses of section range in file
            if srcshdr.sh_type == SHT_NOBITS:
                # NOBITS section don't have data in file
                tmp["data"]["from"] = 0
                tmp["data"]["to"] = 0
            else:
                # determine start of range under construction relativ to the
                # start of its containing section
                if ranges[r][0] < srcshdr.sh_offset:
                    # range under construction starts at the beginning of its
                    # containing section
                    tmp["data"]["from"] = 0
                else:
                    tmp["data"]["from"] = ranges[r][0] - srcshdr.sh_offset
                # range under construction ends at the end of its containing
                # section
                tmp["data"]["to"] = srcshdr.sh_size

                if srcshdr.sh_entsize != 0 and tmp["data"]["from"] % srcshdr.sh_entsize != 0:
                    print_error("In section {0}: range to keep is misaligned by {1} byte(s) (start relative to section start: 0x{2:x}, entrysize: 0x{3:x}, start of problematic range to keep: 0x{4:x})".format(i, tmp["data"]["from"] % srcshdr.sh_entsize, tmp["data"]["from"], srcshdr.sh_entsize, tmp["data"]["from"] + srcshdr.sh_offset))
                    raise cu

                if srcshdr.sh_entsize != 0 and tmp["data"]["to"] % srcshdr.sh_entsize != 0:
                    print_error("In section {0}: range to keep is misaligned by {1} byte(s) (end relative to section start: 0x{2:x}, entrysize: 0x{3:x}, end of problematic range to keep: 0x{4:x})".format(i, tmp["data"]["to"] % srcshdr.sh_entsize, tmp["data"]["to"], srcshdr.sh_entsize, tmp["data"]["to"] + srcshdr.sh_offset))
                    raise cu

            tmp["data"]["section_align"] = srcshdr.sh_addralign
            tmp["data"]["section_offset"] = srcshdr.sh_offset

            # memory layout of section range
            for j in range(0, phdrnum.value):
                srcphdr = GElf_Phdr()
                if libelf.gelf_getphdr(src, c_int(j), byref(srcphdr)) == None:
                    print_error("Could not retrieve source phdr structure {0}: {1}".format(i, libelf.elf_errmsg(c_int(-1))))
                    raise cu

                if srcphdr.p_type != PT_LOAD:
                    # not a loadable segment so it contains no data about the
                    # memory layout of any part of the input file
                    continue

                if srcphdr.p_offset >= srcshdr.sh_offset + (0 if srcshdr.sh_type == SHT_NOBITS else srcshdr.sh_size) or srcphdr.p_offset + (srcphdr.p_memsz if srcshdr.sh_type == SHT_NOBITS else srcphdr.p_filesz) <= srcshdr.sh_offset:
                    # loadable segment but does not load this section
                    continue

                tmp["as"]["loadable"] = True
                tmp["as"]["flags"] = srcphdr.p_flags
                tmp["as"]["align"] = srcphdr.p_align

                if srcshdr.sh_type == SHT_NOBITS:
                    # range contains whole NOBITS section
                    tmp["as"]["from"] = srcshdr.sh_addr
                    tmp["as"]["to"] = tmp["as"]["from"] + srcshdr.sh_size
                else:
                    # determine start and end addresses of section range in memory
                    if srcphdr.p_offset <= srcshdr.sh_offset:
                        # segment starts before section starts
                        tmp["as"]["from"] = srcphdr.p_vaddr + srcshdr.sh_offset + tmp["data"]["from"] - srcphdr.p_offset
                    else:
                        # segment starts after section starts
                        tmp["as"]["from"] = srcphdr.p_offset - srcshdr.sh_offset

                    tmp["as"]["to"] = tmp["as"]["from"] + (tmp["data"]["to"] - tmp["data"]["from"])

                break

            insertRange(tmp, section_ranges[i])

    return section_ranges



def shrinkelf(srcfname, dstfname, ranges):
#-----------------------------------------------------------------------------#
#  Setup                                                                      #
#-----------------------------------------------------------------------------#
    # libelf-library won't work if you don't tell it the ELF version
    if libelf.elf_version(EV_CURRENT) == EV_NONE.value:
        print_error("ELF library initialization failed: ", libelf.elf_errmsg(c_int(-1)));
        exit(1)

    # file descriptor of input file
    srcfd = os.open(srcfname, os.O_RDONLY)
    if srcfd < 0:
        print_error("Could not open input file ", srcfname)
        exit(1)

    cu.level += 1
    try:
        # ELF representation of input file
        srce = libelf.elf_begin(c_int(srcfd), ELF_C_READ, None)
        if srce == None:
            print_error("Could not retrieve ELF structures from input file: ", libelf.elf_errmsg(c_int(-1)));
            raise cu

        cu.level += 1
        # file descriptor of output file
        dstfd = os.open(dstfname, os.O_WRONLY | os.O_CREAT, mode=0o777)
        if dstfd < 0:
            print_error("Could not open output file ", dstfname)
            raise cu

        cu.level += 1
        # ELF representation of output file
        dste = libelf.elf_begin(c_int(dstfd), ELF_C_WRITE, None)
        if dste == None:
            print_error("Could not create ELF structures for output file: ", libelf.elf_errmsg(c_int(-1)));
            raise cu

        cu.level += 1
        # tell lib that the application will take care of the exact file layout
        if libelf.elf_flagelf(dste, ELF_C_SET, ELF_F_LAYOUT) == 0:
            print_error("elf_flagelf() failed: ", libelf.elf_errmsg(c_int(-1)))
            raise cu

        # Specify fill byte for padding -- especially the padding within the
        # .text section. Set to 0xcc because this generates an interrupt on the
        # target platform x86_64.
        libelf.elf_fill(0xcc);

#-----------------------------------------------------------------------------#
#  Copy executable header                                                     #
#-----------------------------------------------------------------------------#
        # ELF class of input file
        elfclass = libelf.gelf_getclass(srce)
        if elfclass == ELFCLASSNONE.value:
            print_error("Could not retrieve ELF class from input file")
            raise cu

        # executable header of input file
        srcehdr = GElf_Ehdr()
        if libelf.gelf_getehdr(srce, pointer(srcehdr)) == None:
            print_error("Could not retrieve executable header from input file: ", libelf.elf_errmsg(c_int(-1)))
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
        dstehdr_pointer = libelf.gelf_newehdr(dste, elfclass)
        if dstehdr_pointer == None:
            print_error("Could not create executable header of output file: ", libelf.elf_errmsg(c_int(-1)))
            raise cu

        dstehdr = dstehdr_pointer.contents
        dstehdr.e_ident[EI_DATA] = srcehdr.e_ident[EI_DATA]
        dstehdr.e_ident[EI_OSABI] = srcehdr.e_ident[EI_OSABI]
        dstehdr.e_ident[EI_ABIVERSION] = srcehdr.e_ident[EI_ABIVERSION]
        dstehdr.e_machine = srcehdr.e_machine
        dstehdr.e_type = srcehdr.e_type
        dstehdr.e_flags = srcehdr.e_flags
        dstehdr.e_shstrndx = srcehdr.e_shstrndx
        dstehdr.e_entry = srcehdr.e_entry

        if libelf.gelf_update_ehdr(dste, dstehdr_pointer) == 0:
            print_error("Could not update ELF structures (Header): ", libelf.elf_errmsg(c_int(-1)));
            raise cu

#-----------------------------------------------------------------------------#
#  Copy program headers                                                       #
#-----------------------------------------------------------------------------#
        # number of sections in input file
        scnnum = c_size_t(0)
        if libelf.elf_getshdrnum(srce, pointer(scnnum)) != 0:
            print_error("Could not retrieve number of sections from input file: ", libelf.elf_errmsg(c_int(-1)))
            raise cu

        section_ranges = computeSectionRanges(srce, ranges, scnnum)

        # number of segments in input file
        phdrnum = c_size_t(0)
        if libelf.elf_getphdrnum(srce, byref(phdrnum)) != 0:
            print_error("Could not retrieve number of segments from input file: ", libelf.elf_errmsg(c_int(-1)))
            raise cu

        # number of LOAD segments in source file
        loads = countLOADs(srce)
        # description of layout of output file
        # TODO:
        desc = calculateNewFilelayout(section_ranges, scnnum, phdrnum - loads, elfclass, args_info.permutate_given)
        ######################################################
        # if (desc == NULL) { goto err_free_section_ranges; }
        ######################################################
        dstehdr.e_phoff = desc["phdr_start"]
        # PHDR table of output file
        dstphdrs = libelf.gelf_newphdr(dste, desc["phdr_entries"])
        if dstphdrs == NULL:
            print_error("Could not create PHDR table for output file: ", libelf.elf_errmsg(c_int(-1)))
            raise cu

        #########################################################
        # errno = 0;
        # // current PHDR entry of input file
        # GElf_Phdr *srcphdr = calloc(1, sizeof(GElf_Phdr));
        # if (srcphdr == NULL) {
        # 	error(0, errno, "Out of memory");
        # 	goto err_free_desc;
        # }
        ##########################################################
        # index of current PHDR entry in output file
        new_index = 0
        # flag if the current LOAD segment is the first of the input file
        first_load = True

        # XXX: Debug
        print("descriptor", desc)
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



if __name__ == "__main__":
#-----------------------------------------------------------------------------#
#  Command line argument processing                                           #
#-----------------------------------------------------------------------------#
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("file", help="the file, which should be shrunk")
    parser.add_argument("-k", "--keep", metavar="RANGE", action='append', help="Keep given %(metavar)s in new file. Accepted formats are\n 'START-END'   exclusive END\n 'START:LEN'   LEN in bytes\nwith common prefixes for base")
    parser.add_argument("-K", "--keep-file", metavar="FILE", help="File to read ranges from")
    parser.add_argument("-p", "--permutate", action='store_true', help="Permutate fragments for potential smaller output file.\nWARNING: The used algorithm is in O(n!)")
    parser.add_argument("-o", "--output-file", metavar="FILE", help="Name of the output file")
    args = parser.parse_args()

    # parse ranges to keep
    if args.keep == None:
        if args.keep_file == None:
            print_error("No ranges specified. Aborting!")
            exit(1)
        else:
            args.keep = []
            for line in open(args.keep_file):
                args.keep.append(line)

    ranges = []
    error = False
    for item in args.keep:
        if ":" in item:
            frag_desc = item.split(":")
            if len(frag_desc) != 2:
                print_error("Invalid range argument '", item, "' - ignoring!")
                error = True
                continue

            try:
                start = int(frag_desc[0], base = 0)
            except ValueError:
                print_error("First part ('", frag_desc[0],"') of range argument '", item, "' not parsable - ignoring!")
                error = True
                continue

            try:
                length = int(frag_desc[1], base = 0)
            except ValueError:
                print_error("Second part ('", frag_desc[1],"') of range argument '", item, "' not parsable - ignoring!")
                error = True
                continue

            if start < 0:
                print_error("START of ", item, "must be bigger than or equal to zero (is ", start, ") - ignoring!")
                error = True
                continue
            if length < 1:
                print_error("LEN of ", item, "must be bigger than zero (is ", length, ") - ignoring!")
                error = True
                continue

            tmp = insertTuple((start, start + length), ranges)
            if tmp != None:
                print_error(item, "overlaps with", tmp)
                error = True
                continue
        elif "-" in item:
            frag_desc = item.split("-")
            if len(frag_desc) != 2:
                print_error("Invalid range argument '", item, "' - ignoring!")
                error = True
                continue

            try:
                start = int(frag_desc[0], base = 0)
            except ValueError:
                print_error("First part ('", frag_desc[0],"') of range argument '", item, "' not parsable - ignoring!")
                error = True
                continue

            try:
                end = int(frag_desc[1], base = 0)
            except ValueError:
                print_error("Second part ('", frag_desc[1],"') of range argument '", item, "' not parsable - ignoring!")
                error = True
                continue

            if start < 0:
                print_error("START of ", item, "must be bigger than or equal to zero (is ", start, ") - ignoring!")
                error = True
                continue
            if end <= start:
                print_error("END of ", item, "must be bigger than START (START: ", start, ", END: ", end, ") - ignoring!")
                error = True
                continue

            tmp = insertTuple((start, end), ranges)
            if tmp != None:
                print_error(item, "overlaps with", tmp)
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
    if args.output_file != None:
        # user specified output file name
        if args.output_file == args.file:
            print_error("Input and output file are the same! Aborting")
            exit(1)
        dstfname = args.output_file
    else:
        # generate own output file name
        dstfname = args.file + FILESUFFIX

    # XXX: Debug
    print(ranges)
    shrinkelf(args.file, dstfname, ranges)
    exit(cu.exitstatus)
