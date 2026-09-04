from dataclasses import dataclass
from numbers import Number

from .core import SATContext
from ..relation import ComponentRelation
from ..util import AND_DIFFERENTIAL_REL, AND_LINEAR_REL

# ----------------------------------------------------------------- *)

type SATClause = tuple[int, ...]
type SATObjectiveTerm = tuple[Number, int]


@dataclass(frozen=True, slots=True)
class PrecomputedSATModel:
    auxiliary_width: int
    clauses: tuple[SATClause, ...]
    objective: tuple[SATObjectiveTerm, ...] = ()


# ----------------------------------------------------------------- *)

# Computed in the same way as is done in
# AND_CVL, using LOGICAL_COND_EPSRESSO

# [ # Sanity check: ]----------------------------------------------- *)
# a=b=0:
#     c=0
#     metric=4
#
# otherwise:
#     c arbitrary
#     metric=2
# which is the ddt:
# (
#     (4, 0),
#     (2, 2),
#     (2, 2),
#     (2, 2),
# )


AND_DIFFERENTIAL_SAT = PrecomputedSATModel(
    auxiliary_width=2,
    clauses=(
        (-1, -5),
        (-2, -5),
        (-3, -5),
        (1, 2, -4),
        (4, 5),
    ),
    objective=(
        (1, 4),
        (0, 5),
    ),
)

# as above:

# [ # Sanity check: ]----------------------------------------------- *)
#  c  OR  p4
#  c  OR ~a
#  c  OR ~b
#  p2 OR ~c
# ~p2 OR ~p4
# c=0:
#     a=b=0
#     metric=4
#
# c=1:
#     a,b arbitrary
#     metric=2
# again, the lat:
# (
#     (4, 2),
#     (0, 2),
#     (0, 2),
#     (0, 2),
# )

AND_LINEAR_SAT = PrecomputedSATModel(
    auxiliary_width=2,
    clauses=(
        (-1, -5),
        (-2, -5),
        (-3, 4),
        (-4, -5),
        (3, 5),
    ),
    objective=(
        (1, 4),
        (0, 5),
    ),
)

# ----------------------------------------------------------------- *)


_PRECOMPUTED = {
    AND_DIFFERENTIAL_REL: AND_DIFFERENTIAL_SAT,
    AND_LINEAR_REL: AND_LINEAR_SAT,
}


def get_precomputed_sat_model(rel: ComponentRelation) -> PrecomputedSATModel | None:
    return _PRECOMPUTED.get(rel, None)


def encode_precomputed_sat(precomputed: PrecomputedSATModel, ctx: SATContext) -> None:
    """nil

    NOTES:
    * DIMACS numbering

    """

    from ...util import translate_sat_clause

    auxiliary = tuple(ctx.model.var() for _ in range(precomputed.auxiliary_width))
    variables = (*ctx.IN, *ctx.OUT, *auxiliary)

    for clause in precomputed.clauses:
        ctx.model.add_clause(translate_sat_clause(variables, clause))

    scale = 10**ctx.options.sat_precision

    ctx.objective.extend(
        (scale * weight, variables[variable - 1])
        for weight, variable in precomputed.objective
    )
