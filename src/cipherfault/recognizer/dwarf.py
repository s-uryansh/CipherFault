"""DWARF-backed source regions for recognizer ground truth."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from elftools.dwarf.descriptions import describe_form_class
from elftools.dwarf.ranges import BaseAddressEntry
from elftools.elf.elffile import ELFFile

from ..lifting.types import LiftedFunction
from ..regions.extractor import extract_regions


@dataclass(frozen=True)
class SourceRange:
    start: int
    end: int
    source: str
    names: tuple[str, ...]
    inline: bool


def source_ranges(binary: str | Path) -> list[SourceRange]:
    with Path(binary).open("rb") as stream:
        dwarf = ELFFile(stream).get_dwarf_info()
        ranges = []
        for cu in dwarf.iter_CUs():
            files = _file_table(dwarf, cu)
            for die in cu.iter_DIEs():
                if die.tag not in {"DW_TAG_subprogram", "DW_TAG_inlined_subroutine"}:
                    continue
                origin = _origin(die)
                source = files.get(_value(origin, "DW_AT_decl_file"), "")
                names = tuple(filter(None, (_text(origin, "DW_AT_name"), _text(origin, "DW_AT_linkage_name"))))
                for start, end in _die_ranges(dwarf, cu, die):
                    ranges.append(SourceRange(start, end, source, names, die.tag == "DW_TAG_inlined_subroutine"))
        return ranges


def labeled_regions(function: LiftedFunction, ranges: list[SourceRange], source_file: str) -> list[tuple[set[str], bool]]:
    """Return connected block regions labeled by whether DWARF maps them to source_file."""
    labels = _block_labels(function, ranges, source_file)

    regions = []
    graph = function.cfg.to_undirected()
    unseen = set(function.blocks)
    while unseen:
        seed = unseen.pop()
        label = labels[seed]
        component = {seed}
        pending = [seed]
        while pending:
            node = pending.pop()
            for neighbor in graph.neighbors(node) if node in graph else ():
                if neighbor in unseen and labels.get(neighbor) == label:
                    unseen.remove(neighbor)
                    component.add(neighbor)
                    pending.append(neighbor)
        regions.append((component, label))
    return regions


def candidate_labeled_regions(
    function: LiftedFunction, ranges: list[SourceRange], source_file: str
) -> list[tuple[set[str], bool]]:
    """Label deployment-shaped regions by whether they contain target-source code."""
    labels = _block_labels(function, ranges, source_file, include_sibling_sources=True)
    return [(region, any(labels.get(address, False) for address in region)) for region in extract_regions(function)]


def _block_labels(
    function: LiftedFunction,
    ranges: list[SourceRange],
    source_file: str,
    include_sibling_sources: bool = False,
) -> dict[str, bool]:
    bias = _image_bias(function, ranges)
    target = Path(source_file).as_posix()
    labels = {}
    for address, block in function.blocks.items():
        instruction_addresses = block.instruction_addresses or [address]
        matches = [_range_at(_address(value) - bias, ranges) for value in instruction_addresses]
        mapped = [match for match in matches if match is not None]
        labels[address] = bool(mapped) and any(
            _same_source(match.source, target)
            or (include_sibling_sources and _same_source_directory(match.source, target))
            for match in mapped
        )
    return labels


def _image_bias(function: LiftedFunction, ranges: list[SourceRange]) -> int:
    entry = _address(function.entry)
    base_name = function.name.removesuffix(".cold")
    candidates = [entry - item.start for item in ranges if base_name in item.names and not item.inline]
    aligned = [candidate for candidate in candidates if candidate >= 0 and candidate % 0x1000 == 0]
    return Counter(aligned or candidates).most_common(1)[0][0] if candidates else 0


def _range_at(address: int, ranges: list[SourceRange]) -> SourceRange | None:
    matches = [item for item in ranges if item.start <= address < item.end]
    return min(matches, key=lambda item: item.end - item.start) if matches else None


def _same_source(actual: str, expected: str) -> bool:
    actual_path = Path(actual).as_posix()
    return actual_path == expected or actual_path.endswith("/" + expected) or expected.endswith("/" + actual_path)


def _same_source_directory(actual: str, expected: str) -> bool:
    actual_parent = Path(actual).parent.as_posix()
    expected_parent = Path(expected).parent.as_posix()
    return (
        actual_parent == expected_parent
        or actual_parent.endswith("/" + expected_parent)
        or expected_parent.endswith("/" + actual_parent)
    )


def _address(value: str) -> int:
    return int(value.split(":")[-1], 16)


def _file_table(dwarf, cu) -> dict[int, str]:
    program = dwarf.line_program_for_CU(cu)
    if program is None:
        return {}
    header = program.header
    directories = [entry.decode(errors="replace") for entry in header.include_directory]
    dwarf5 = header.version >= 5
    result = {}
    for index, entry in enumerate(header.file_entry, 0 if dwarf5 else 1):
        name = entry.name.decode(errors="replace")
        directory_index = entry.dir_index
        directory = directories[directory_index if dwarf5 else directory_index - 1] if directory_index else ""
        result[index] = str(Path(directory, name)) if directory else name
    return result


def _origin(die):
    attribute = die.attributes.get("DW_AT_abstract_origin") or die.attributes.get("DW_AT_specification")
    return die.get_DIE_from_attribute(attribute.name) if attribute else die


def _value(die, name: str):
    attribute = die.attributes.get(name)
    return attribute.value if attribute else None


def _text(die, name: str) -> str:
    value = _value(die, name)
    return value.decode(errors="replace") if isinstance(value, bytes) else str(value or "")


def _die_ranges(dwarf, cu, die):
    low = die.attributes.get("DW_AT_low_pc")
    high = die.attributes.get("DW_AT_high_pc")
    if low and high:
        end = high.value if describe_form_class(high.form) == "address" else low.value + high.value
        return [(low.value, end)]
    attribute = die.attributes.get("DW_AT_ranges")
    if not attribute:
        return []
    base = 0
    result = []
    for entry in dwarf.range_lists().get_range_list_at_offset(attribute.value, cu):
        if isinstance(entry, BaseAddressEntry):
            base = entry.base_address
        else:
            start = entry.begin_offset if entry.is_absolute else base + entry.begin_offset
            end = entry.end_offset if entry.is_absolute else base + entry.end_offset
            result.append((start, end))
    return result
