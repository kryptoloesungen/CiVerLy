"""
Pure utilities which are either more generic then the encoding specific functions
in `tools.py` or are entirely standalone.

"""

from typing import Any

#
from .. import model_options as MO
from ..component import Component

from functools import cache
from sage.crypto.sbox import SBox


def int_to_bits(integer: int, width: int) -> tuple[int, ...]:
    return tuple(int(bit) for bit in f"{integer:0{width}b}")


def bits_to_int(bits: tuple[int, ...]) -> int:
    return int("".join(str(x) for x in bits), base=2)


def type_name(obj: Any) -> str:
    return type(obj).__name__


def _transition_table(sbox: SBox, analysis: MO.CRYPTANALYSIS):
    """nil"""

    match analysis:
        case MO.CRYPTANALYSIS.DIFFERENTIAL:
            return sbox.difference_distribution_table()
        case MO.CRYPTANALYSIS.LINEAR:
            # use LAT instead of DDT
            return [
                [abs(int(entry * len(sbox))) for entry in row]
                for row in sbox.linear_approximation_table("correlation")
            ]
        case _:
            raise ValueError()


def _wordcoarse_perm_table(table, wc: int) -> tuple[int]:
    return tuple(wc * table[i] + j for i in range(len(table)) for j in range(wc))


def _get_divide_factor(component: Component, options: MO.MODEL_OPTIONS):
    return component.wordsize if options.granularity == MO.GRANULARITY.WORDWISE else 1
