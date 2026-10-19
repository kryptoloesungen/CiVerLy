"""
Various utility functions / shared code across all different analysis types / optimisation problems.
"""

from functools import cache
from itertools import product
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING
from typing_extensions import Literal


#
from sage.crypto.sbox import SBox

#
from .. import model_options as MO
from ..component import Component, LinearLayer_CVL, SBox_CVL


if TYPE_CHECKING:
    from .milp.core import MILPContext
    from .. import model_options as MO

# [ Standalone ]---------------------------------------------------- *)

Bit = Literal[0, 1]


def _get_divide_factor(component: Component, options: MO.MODEL_OPTIONS):
    return component.wordsize if options.granularity == MO.GRANULARITY.WORDWISE else 1


def int_to_bits(integer: int, width: int) -> tuple[int, ...]:
    return tuple(int(bit) for bit in f"{integer:0{width}b}")


def bits_to_int(bits: tuple[int, ...]) -> int:
    return int("".join(str(x) for x in bits), base=2)


def type_name(obj: Any) -> str:
    return type(obj).__name__


# [ All those damn tables ]----------------------------------------- *)


def _identity_table(width: int) -> tuple[int]:
    return tuple(range(width))


def _rotation_table(width: int, degree: int) -> tuple[int]:
    return tuple(range((-degree) % width, width)) + tuple(range((-degree) % width))


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


# [ Utilities for probabilistic transitions ]----------------------- *)


@dataclass(frozen=True, slots=True)
class WeightedTransition:
    bits: tuple[Bit, ...]
    # Example for a 2 -> 1 relation:
    #     bits = (1, 0, 1) -> read (1, 0) -> (1,)

    metric: int
    # weight associated with the transition
    #
    # using 'metric' (weight, probability, correlation),
    # although it should probs be 'weight'


@dataclass(frozen=True, slots=True)
class WeightedTransitions:
    # All permitted input/output transitions,
    # together with their metrics.
    transitions: tuple[WeightedTransition, ...]

    # normaliser / scaler used to convert transition metrics
    # into objective weights
    #
    # typical expression everywhere:
    #     weight = -log2(metric / normaliser)
    #
    # e.g. for n-bit S-Box is 2^n
    normalizer: int


@cache
def _weighted_transition_rel(
    sbox_table: tuple[int, ...], analysis: MO.CRYPTANALYSIS
) -> WeightedTransitions:
    """nil"""

    from sage.crypto.sbox import SBox
    from .tools import _transition_table, int_to_bits

    sbox = SBox(list(sbox_table))
    table = _transition_table(sbox, analysis)

    # input/output width
    iw = sbox.input_size()
    ow = sbox.output_size()

    def _get_bits(i, o):
        return (*int_to_bits(i, iw), *int_to_bits(o, ow))

    transitions = tuple(
        WeightedTransition(_get_bits(i, o), int(table[i][o]))
        for i in range(1 << iw)
        for o in range(1 << ow)
        if table[i][o] > 0
    )

    return WeightedTransitions(iw, ow, transitions, int(table[0][0]))


# [ Parity and Linear Layer utils ]--------------------------------- *)

@dataclass(frozen=True, slots=True)
class ParityEquation:
    """indices of all variables in one XOR equation

    assuminig flat local namespace:
        [IN..., OUT...] = [0, ... , |IN| - 1, |IN|, ... , |OUT| - 1]

    Example:
        variables = (0, 2, 5), rhs = 0

    means:
        VAR[0] XOR VAR[2] XOR VAR[5] = 0
    """

    variables: tuple[int, ...]

    # right hand side
    rhs: Bit = 0


def _linear_layer_equations(matrix, IN, OUT) -> tuple[ParityEquation, ...]:
    equations = tuple(
        # parity equation to exclude assignments with odd HW (hence, rhs = 0)
        ParityEquation(
            (
                *tuple(IN[i] for i, entry in enumerate(row) if entry == 1),
                OUT[row_index],
            ),
            rhs=0,
        )
        for row_index, row in enumerate(matrix)
    )

    return equations


def _parity_violating_assignments(n: int, rhs: int):
    return (assignment for assignment in product((0, 1), repeat=n) if sum(assignment) % 2 != rhs)


#
# @Inbook{Lancia2018,
# author="Lancia, Giuseppe
# and Serafini, Paolo",
# title="The Parity Polytope",
# bookTitle="Compact Extended Linear Programming Models",
# year="2018",
# publisher="Springer International Publishing",
# address="Cham",
# pages="113--121",
# abstract="This chapter is focused on the parity polytope, i.e., the convex hull of all 0-1 vectors with an even number of ones. A closely related polytope is the convex hull of all 0-1 vectors with an odd number of ones. We show two alternative compact extended formulations for both polytopes, one based on the union of polyhedra and the other one on LP. Whereas the former is a quadratic extension, the latter is only linear. This result seems to be new.",
# isbn="978-3-319-63976-5",
# doi="10.1007/978-3-319-63976-5_8",
# url="https://doi.org/10.1007/978-3-319-63976-5_8"
# }
#


def _even_parity_polytope_h_form():
    """
    Let F be a subset of {0, 1, ..., n - 1} and let |F| = 1 mod 2.

    External representation:
        sum_{i in F} zi - sum_{i not in F} zi <= |F| - 1

    Rearanging variables:
        sum_{i in F} (1 - zi) - sum_{i not in F} zi >= 1


    """
    return
