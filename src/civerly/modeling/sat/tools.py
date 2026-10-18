import zlib
from dataclasses import dataclass
from itertools import product
from functools import cache
from math import log2
from numbers import Number
from pathlib import Path

#
from ... import model_options as MO
from ...component import SBox_CVL, AND_CVL

#
from ..tools import _weighted_transition_rel
from ..tools import WeightedTransitions

#
from .core import SATVar, SATContext

# [ Utilities for _SAT encoding_ of probablistic transitions ]------ *)
#
#
# [ # main ]-------------------------------------------------------- *)
#
#
# USING from the olde stuff:
#
#     set_ddt = tuple(sorted({value for row in ddt for value in row if value > 0}))
#     map_ddt_val_idx = {value: index for index, value in enumerate(set_ddt)}
#
#     # skipping ahead...
#
#     p_arr = [0 for _ in set_ddt]
#     p_arr[map_ddt_val_idx[ddt_value]] = 1
#     posset.append((*i_binarr, *o_binarr, *p_arr))
#
#     PROB_VARS = tuple(ctx.model.var() for _ in set_ddt)
#     VARS = (*ctx.IN, *ctx.OUT, *PROB_VARS)


@dataclass(frozen=True, slots=True)
class WeightedTransitionData:
    metrics: tuple[int, ...]
    posset: tuple[tuple[int, ...], ...]
    metric_vars: tuple[SATVar, ...]
    variables: tuple[SATVar, ...]


@cache
def _get_weighted_transition_data(
    rel: WeightedTransitions,
    analysis: MO.CRYPTANALYSIS,
) -> tuple[tuple[int, ...], tuple[tuple[int, ...], ...]]:
    r"""nil"""

    metrics = tuple(sorted({transition.metric for transition in rel.transitions}))
    metric_index = {metric: i for i, metric in enumerate(metrics)}

    # fmt: off
    posset = tuple(
        (
            *transition.bits,
            *(
              int(i == metric_index[transition.metric]) 
              for i in range(len(metrics))
             ),
        )
        for transition in rel.transitions
    )
    # fmt: on

    return metrics, posset


def _prepare_weighted_transition_sat(
    rel: WeightedTransitions,
    analysis: MO.CRYPTANALYSIS,
    ctx: SATContext,
) -> WeightedTransitionData:
    """Split into multiple parts or caching"""

    metrics, posset = _get_weighted_transition_data(rel, analysis)
    metric_vars = tuple(ctx.model.var() for _ in metrics)
    variables = (*ctx.IN, *ctx.OUT, *metric_vars)

    return WeightedTransitionData(
        metrics=metrics,
        posset=tuple(posset),
        metric_vars=metric_vars,
        variables=variables,
    )


# [ # weighted transitions: objective ]----------------------------- *)


def _weighted_transition_objective_sat(
    rel: WeightedTransitions,
    data: WeightedTransitionData,
    ctx: SATContext,
) -> None:
    """nil"""

    precision = ctx.options.sat_precision
    scale = 10**precision

    ctx.objective.extend(
        (-int(scale * log2(metric / rel.normalizer)), metric_var)
        for metric, metric_var in zip(data.metrics, data.metric_vars, strict=False)
    )


# [ # weighted transition: espresso utility ]----------------------- *)


@cache
def _get_espresso_clauses(rel: WeightedTransitions):
    import os
    import subprocess

    if "CIVERLY_DISABLE_ESPRESSO" in os.environ:
        raise ValueError(
            "ESPRESSO was disabled by setting environment variable CIVERLY_DISABLE_ESPRESSO"
        )

    _, posset = _get_weighted_transition_data(rel)

    # create espresso input
    espresso_input = [f".i {len(posset[0])}", ".o 1"]
    for possible_transition in posset:
        espresso_input.append("".join([str(t) for t in possible_transition]) + " 1")
    espresso_input.append(".e")
    espresso_input = "\n".join(espresso_input) + "\n"

    # execute espresso process
    # ``-epos`` aims to only generate clauses that must be fulfilled (with
    # '1' at the end of the line),
    # which is what we need to generate a CNF for posset.
    espresso_process = subprocess.run(
        ["espresso", "-epos"], input=espresso_input, capture_output=True, text=True
    )
    espresso_output = espresso_process.stdout.splitlines()

    clauses = []
    for line in espresso_output:
        if line[0] not in ["0", "1", "-"]:
            continue  # skip the header lines
        if line[-1] == "1":  # only take the CNF-clauses
            # i+1 to avoid sign errors
            # NOTE: in post-processing, we must subtract -1 again
            clause = tuple(
                (-1) ** int(line[i]) * (i + 1) for i in range(len(posset[0])) if line[i] != "-"
            )
            clauses.append(clause)
    return tuple(clauses)


# [ Precomputation ]------------------------------------------------ *)
#
#
# [ # Two-Bit AND ]------------------------------------------------- *)
#
# precomputation for the 2-to-1 bit ANDs (x AND y)

_AND_DIFFERENTIAL_TABLE = (
    (4, 0),
    (2, 2),
    (2, 2),
    (2, 2),
)

_AND_LINEAR_TABLE = (
    (4, 2),
    (0, 2),
    (0, 2),
    (0, 2),
)


# [ ABG Helper for ModAdd encoding ]-------------------------------- *)


def _encode_abg_helper(ctx: SATContext, width: int):
    alpha = [ctx.IN[i] for i in range(width)]
    beta = [ctx.IN[i + width] for i in range(width)]
    gamma = [ctx.OUT[i] for i in range(width)]
    return alpha, beta, gamma


# [ Encoding "Parity" Equations; Relevant for XOR / LinearLayer ]--- *)


def _encode_parity_equation_direct_sat(
    variables: tuple[SATVar, ...], rhs: int, ctx: SATContext
) -> None:

    # [@imp being obnoxious]
    for assignment in product((0, 1), repeat=len(variables)):
        if sum(assignment) % 2 == rhs:
            continue

        ctx.model.add_clause(
            tuple(-var if value else var for var, value in zip(variables, assignment, strict=False))
        )
