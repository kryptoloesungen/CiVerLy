"""
Pure utilities which are either more generic then the encoding specific functions
in `tools.py` or are entirely standalone.

"""

from typing import Any
from ..model_options import CRYPTANALYSIS

from functools import cache
from sage.crypto.sbox import SBox


def int_to_bits(integer: int, width: int) -> tuple[int, ...]:
    return tuple(int(bit) for bit in f"{integer:0{width}b}")


def bits_to_int(bits: tuple[int, ...]) -> int:
    return int("".join(str(x) for x in bits), base=2)


def type_name(obj: Any) -> str:
    return type(obj).__name__


def _transition_table(sbox: SBox, analysis: CRYPTANALYSIS):
    """nil"""

    match analysis:
        case CRYPTANALYSIS.DIFFERENTIAL:
            return sbox.difference_distribution_table()
        case CRYPTANALYSIS.LINEAR:
            # use LAT instead of DDT
            return [
                [abs(int(entry * len(sbox))) for entry in row]
                for row in sbox.linear_approximation_table("correlation")
            ]
        case _:
            raise ValueError()



