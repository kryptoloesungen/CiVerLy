import zlib
from dataclasses import dataclass
from itertools import product
from functools import cache
from math import log2
from numbers import Number
from pathlib import Path

from .core import SATVar, SATContext
from ..relation import WeightedTransitionRelation

# ----------------------------------------------------------------- *)


@dataclass(frozen=True, slots=True)
class WeightedTransitionSATData:
    metrics: tuple[int, ...]
    posset: tuple[tuple[int, ...], ...]
    metric_vars: tuple[SATVar, ...]
    variables: tuple[SATVar, ...]


# USING:
#     set_ddt = tuple(sorted({value for row in ddt for value in row if value > 0}))
#     map_ddt_val_idx = {value: index for index, value in enumerate(set_ddt)}
#
#     # more stuff...
#
#     p_arr = [0 for _ in set_ddt]
#     p_arr[map_ddt_val_idx[ddt_value]] = 1
#     posset.append((*i_binarr, *o_binarr, *p_arr))
#
#     PROB_VARS = tuple(ctx.model.var() for _ in set_ddt)
#     VARS = (*ctx.IN, *ctx.OUT, *PROB_VARS)


@cache
def _get_weighted_transition_data(
    rel: WeightedTransitionRelation,
) -> tuple[tuple[int, ...], tuple[tuple[int, ...], ...]]:
    metrics = tuple(sorted({transition.metric for transition in rel.transitions}))
    metric_index = {metric: i for i, metric in enumerate(metrics)}

    posset = tuple(
        (
            *transition.bits,
            *(int(i == metric_index[transition.metric]) for i in range(len(metrics))),
        )
        for transition in rel.transitions
    )

    return metrics, posset


# ----------------------------------------------------------------- *)


def _weighted_transition_objective_sat(
    rel: WeightedTransitionRelation,
    data: WeightedTransitionSATData,
    ctx: SATContext,
    precision: Number,
) -> None:
    scale = 10**precision

    ctx.objective.extend(
        (-int(scale * log2(metric / rel.normalizer)), metric_var)
        for metric, metric_var in zip(data.metrics, data.metric_vars, strict=False)
    )

# ----------------------------------------------------------------- *)

def _prepare_weighted_transition_sat(
    rel: WeightedTransitionRelation, ctx: SATContext
) -> WeightedTransitionSATData:

    metrics, posset = _get_weighted_transition_data(rel)

    metric_vars = tuple(ctx.model.var() for _ in metrics)
    variables = (*ctx.IN, *ctx.OUT, *metric_vars)

    return WeightedTransitionSATData(
        metrics=metrics,
        posset=tuple(posset),
        metric_vars=metric_vars,
        variables=variables,
    )

# ----------------------------------------------------------------- *)

@cache
def _get_espresso_clauses(
    rel: WeightedTransitionRelation, logic_minimizer, path: str | Path
):
    path = Path(path)
    _, posset = _get_weighted_transition_data(rel)

    serialized = "".join(
        str(int("".join(map(str, pos)), 2)) for pos in sorted(posset)
    ).encode("utf-8")

    checksum = zlib.crc32(serialized)
    pla_path = path / f"espresso-{checksum:x}.pla"

    return tuple(logic_minimizer.solve(pla_path, posset))


# ----------------------------------------------------------------- *)


def _encode_abg_helper(ctx: SATContext, width: int):
    alpha = [ctx.IN[i] for i in range(width)]
    beta = [ctx.IN[i + width] for i in range(width)]
    gamma = [ctx.OUT[i] for i in range(width)]
    return alpha, beta, gamma


# ----------------------------------------------------------------- *)


def _encode_parity_equation_direct_sat(
    variables: tuple[SATVar, ...], rhs: int, ctx: SATContext
) -> None:

    # [@imp being obnoxious]
    for assignment in product((0, 1), repeat=len(variables)):
        if sum(assignment) % 2 == rhs:
            continue

        ctx.model.add_clause(
            tuple(
                -var if value else var
                for var, value in zip(variables, assignment, strict=False)
            )
        )
