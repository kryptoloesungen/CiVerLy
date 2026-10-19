import zlib
from dataclasses import dataclass
from itertools import product
from functools import cache
from math import log2
from numbers import Number
from pathlib import Path
from collections.abc import Callable

#
from ... import model_options as MO
from ...component import (
    AND_CVL,
    C_CVL,
    I_CVL,
    XOR_CVL,
    Component,
    ConstXOR_CVL,
    LinearLayer_CVL,
    RotateLayer_CVL,
    ModAdd_CVL,
    PermuteLayer_CVL,
    SBox_CVL,
    ROT_AND_CVL,
)


#
from ..tools import _weighted_transition_rel
from ..tools import WeightedTransitions, Bit
from ..tools import ParityEquation
from ..tools import _parity_violating_assignments

#
from .core import SATVar, SATContext


# [ Bit Permutations ]---------------------------------------------- *)


def _encode_permutation_sat(table: tuple[int], ctx: SATContext) -> None:
    for i, j in enumerate(table):
        ctx.model.add_clause((ctx.OUT[j], -ctx.IN[i]))
        ctx.model.add_clause((-ctx.OUT[j], ctx.IN[i]))


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


def _parity_three_xor(width: int):
    # fmt: off
    return tuple(
        ParityEquation((i, i + width, i + 2 * width)) 
        for i in range(width)
    )
    # fmt: on


def _parity_equality(width: int):
    # fmt: off
    return tuple(
        ParityEquation(vars) 
        for i in range(width) 
        for vars in ((i, i + width), (i, i + 2 * width))
    )
    # fmt: on


# fmt: off
def _encode_parity_equation_direct_sat(variables: tuple[SATVar, ...], rhs: int, ctx: SATContext) -> None:

    # This will exclude constraints of the type XOR_i vi != rhs
    #
    # So, if rhs == 0, we are excluding assignments with odd HW
    for assignment in _parity_violating_assignments(n=len(variables), rhs=rhs):
        ctx.model.add_clause(tuple(
            -var if value else var 
            for var, value in zip(variables, assignment, strict=False)
        ))
# fmt: on


def _encode_xor_equations(ctx: SATContext, equations: tuple[ParityEquation, ...]) -> None:
    variables = (*ctx.IN, *ctx.OUT)

    for equation in equations:
        eqvars = tuple(variables[i] for i in equation.variables)
        _encode_parity_equation_direct_sat(eqvars, equation.rhs, ctx)


# [ Helpers for linear layer encoding ]----------------------------- *)


def _two_bit_xor_linear(vars):
    x1, x2, x3 = vars
    return (x1, x2), (x1, x3)


def _two_bit_xor_differential(vars):
    x1, x2, x3 = vars
    return ((x1, x2, x3),)


def _linear_layer_more_dummies(
    ctx: SATContext,
    equations: tuple[ParityEquation, ...],
    two_bit_xor_f: Callable[[tuple[SATVar, ...]], tuple[tuple[SATVar]]],
):
    """nil"""
    for equation in equations:
        active_vars = equation.variables

        if len(active_vars) <= 2:
            _encode_parity_equation_direct_sat(active_vars, equation.rhs, ctx)
            continue

        current_node = active_vars[0]
        for variable in active_vars[1:-2]:
            alpha = current_node
            beta = variable
            gamma = ctx.model.var()
            VAR = (alpha, beta, gamma)
            for eq in two_bit_xor_f(VAR):
                _encode_parity_equation_direct_sat(eq, 0, ctx)
            current_node = gamma

        alpha = current_node
        beta = active_vars[-2]
        gamma = active_vars[-1]
        VAR = (alpha, beta, gamma)

        for eq in two_bit_xor_f(VAR):
            _encode_parity_equation_direct_sat(eq, equation.rhs, ctx)
    return


def _encode_linear_layer_exclude_odd(
    component: LinearLayer_CVL,
    ctx: SATContext,
    encode_linear_layer: Callable[[Component, SATContext], tuple[ParityEquation, ...], Callable],
) -> None:
    """nil"""
    equations, _ = encode_linear_layer(component, ctx)
    _encode_xor_equations(ctx, equations)
    return


def _encode_linear_layer_more_dummies(
    component: LinearLayer_CVL,
    ctx: SATContext,
    encode_linear_layer: Callable[[Component, SATContext], tuple[ParityEquation, ...], Callable],
) -> None:
    """nil"""

    equations, two_bit_xor_f = encode_linear_layer(component, ctx)
    _linear_layer_more_dummies(ctx, equations, two_bit_xor_f)
    return
