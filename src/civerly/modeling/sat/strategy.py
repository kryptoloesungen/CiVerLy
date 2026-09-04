from ...util import translate_sat_clause
from ..relation import (
    DifferentialModAddRelation,
    FixedValueRelation,
    LinearModAddRelation,
    ParallelRelation,
    ParityRelation,
    PermutationRelation,
    TrivialRelation,
    WeightedTransitionRelation,
)
from ..util import bits_to_int
from .util import (
    _encode_abg_helper,
    _encode_parity_equation_direct_sat,
    _get_espresso_clauses,
    _prepare_weighted_transition_sat,
    _weighted_transition_objective_sat,
)
from .core import SATContext

# *⟨ Trivial Relations ⟩--------------------------------------------*


def encode_permutation_sat(rel: PermutationRelation, ctx: SATContext) -> None:
    for i, j in enumerate(rel.table):
        ctx.model.add_clause((ctx.OUT[j], -ctx.IN[i]))
        ctx.model.add_clause((-ctx.OUT[j], ctx.IN[i]))


def encode_fixed_value_sat(rel: FixedValueRelation, ctx: SATContext) -> None:
    for variable, value in zip(ctx.OUT, rel.output_value, strict=False):
        ctx.model.add_clause((variable if value else -variable,))


def encode_trivial_sat(rel: TrivialRelation, ctx: SATContext) -> None:
    pass


# *⟨ Generic Relations ⟩--------------------------------------------*


def encode_parity_direct_sat(rel: ParityRelation, ctx: SATContext) -> None:
    variables = (*ctx.IN, *ctx.OUT)

    for equation in rel.equations:
        eqvars = tuple(variables[i] for i in equation.variables)
        _encode_parity_equation_direct_sat(eqvars, equation.rhs, ctx)


def encode_parity_dummies_sat(rel: ParityRelation, ctx: SATContext) -> None:
    variables = (*ctx.IN, *ctx.OUT)

    for equation in rel.equations:
        eqvars = tuple(variables[i] for i in equation.variables)

        if len(eqvars) <= 3:
            _encode_parity_equation_direct_sat(eqvars, equation.rhs, ctx)
            continue

        current_node = eqvars[0]

        for variable in eqvars[1:-2]:
            next_node = ctx.model.var()
            _encode_parity_equation_direct_sat(
                (current_node, variable, next_node), 0, ctx
            )
            current_node = next_node

        _encode_parity_equation_direct_sat(
            (current_node, eqvars[-2], eqvars[-1]), equation.rhs, ctx
        )


# *⟨ WeightedTransitionRelation ⟩----------------------------------------*


def encode_weighted_transition_direct_sat(
    rel: WeightedTransitionRelation, ctx: SATContext
) -> None:

    data = _prepare_weighted_transition_sat(rel, ctx)

    posset_int = {bits_to_int(transition) for transition in data.posset}

    var_cnt = len(data.variables)
    for transition in range(1 << var_cnt):
        if transition in posset_int:
            continue

        clause = tuple(
            -variable if transition >> (var_cnt - i - 1) & 1 else variable
            for i, variable in enumerate(data.variables)
        )
        ctx.model.add_clause(clause)

    _weighted_transition_objective_sat(
        rel, data, ctx, precision=ctx.options.sat_precision
    )


# *⟨ ## Espresso ⟩----------------------------------------------------*


def encode_weighted_transition_espresso_sat(
    rel: WeightedTransitionRelation, ctx: SATContext
) -> None:

    data = _prepare_weighted_transition_sat(rel, ctx)

    clauses = _get_espresso_clauses(
        rel,
        ctx.options.logic_minimizer,
        ctx.options.path,
    )

    for clause in clauses:
        ctx.model.add_clause(translate_sat_clause(data.variables, clause))

    _weighted_transition_objective_sat(rel, data, ctx)


# *⟨ Modular Addition ⟩----------------------------------------------*


def encode_mod_add_differential_sat(
    rel: DifferentialModAddRelation, ctx: SATContext
) -> None:
    n = rel.width
    alpha, beta, gamma = _encode_abg_helper(ctx, n)

    # fmt: off
    # NOTE that alpha[n-1] is LSB and alpha[0] is MSB
    # Clauses for ModAdd (excluding LSB)
    for i in range(n - 1):
        ctx.model.add_clause((alpha[i], beta[i], -gamma[i], alpha[i+1], beta[i+1], gamma[i+1]))
        ctx.model.add_clause((alpha[i], -beta[i], gamma[i], alpha[i+1], beta[i+1], gamma[i+1]))
        ctx.model.add_clause((-alpha[i], beta[i], gamma[i], alpha[i+1], beta[i+1], gamma[i+1]))
        ctx.model.add_clause((-alpha[i], -beta[i], -gamma[i], alpha[i+1], beta[i+1], gamma[i+1]))
        ctx.model.add_clause((alpha[i], beta[i], gamma[i], -alpha[i+1], -beta[i+1], -gamma[i+1]))
        ctx.model.add_clause((alpha[i], -beta[i], -gamma[i], -alpha[i+1], -beta[i+1], -gamma[i+1]))
        ctx.model.add_clause((-alpha[i], beta[i], -gamma[i], -alpha[i+1], -beta[i+1], -gamma[i+1]))
        ctx.model.add_clause((-alpha[i], -beta[i], gamma[i], -alpha[i+1], -beta[i+1], -gamma[i+1]))

    ctx.model.add_clause((alpha[n-1], beta[n-1], -gamma[n-1]))
    ctx.model.add_clause((alpha[n-1], -beta[n-1], gamma[n-1]))
    ctx.model.add_clause((-alpha[n-1], beta[n-1], gamma[n-1]))
    ctx.model.add_clause((-alpha[n-1], -beta[n-1], -gamma[n-1]))

    PROB = [ctx.model.var() for _ in range(n - 1)]

    # encode probability
    # ---------------------------------------------------------------------------
    for i in range(n - 1):
        ctx.model.add_clause((-alpha[i+1], gamma[i+1], PROB[i]))
        ctx.model.add_clause((beta[i+1], -gamma[i+1], PROB[i]))
        ctx.model.add_clause((alpha[i+1], -beta[i+1], PROB[i]))
        ctx.model.add_clause((alpha[i+1], beta[i+1], gamma[i+1], -PROB[i]))
        ctx.model.add_clause((-alpha[i+1], -beta[i+1], -gamma[i+1], -PROB[i]))

        ctx.objective += [
            (1 * 10**ctx.options.sat_precision, PROB[i])
        ]
    # fmt: on


# ----------------------------------------------------------------- *)


def encode_mod_add_linear_sat(rel: LinearModAddRelation, ctx: SATContext) -> None:
    n = rel.width
    alpha, beta, gamma = _encode_abg_helper(ctx, n)

    PROB = [ctx.model.var() for _ in range(n)]

    # PROB[0] == 0
    ctx.model.add_clause((-PROB[0],))

    # alpha[0] + beta[0] + gamma[0] + PROB[1] == 0
    ctx.model.add_clause((alpha[0], beta[0], gamma[0], -PROB[1]))
    ctx.model.add_clause((alpha[0], beta[0], -gamma[0], PROB[1]))
    ctx.model.add_clause((alpha[0], -beta[0], gamma[0], PROB[1]))
    ctx.model.add_clause((-alpha[0], beta[0], gamma[0], PROB[1]))
    ctx.model.add_clause((alpha[0], -beta[0], -gamma[0], -PROB[1]))
    ctx.model.add_clause((-alpha[0], beta[0], -gamma[0], -PROB[1]))
    ctx.model.add_clause((-alpha[0], -beta[0], gamma[0], -PROB[1]))
    ctx.model.add_clause((-alpha[0], -beta[0], -gamma[0], PROB[1]))

    # alpha[j] + beta[j] + gamma[j] + PROB[j] + PROB[j+1] == 0
    for j in range(1, n - 1):
        ctx.model.add_clause((alpha[j], beta[j], gamma[j], PROB[j], -PROB[j + 1]))
        ctx.model.add_clause((alpha[j], beta[j], gamma[j], -PROB[j], PROB[j + 1]))
        ctx.model.add_clause((alpha[j], beta[j], -gamma[j], PROB[j], PROB[j + 1]))
        ctx.model.add_clause((alpha[j], -beta[j], gamma[j], PROB[j], PROB[j + 1]))
        ctx.model.add_clause((-alpha[j], beta[j], gamma[j], PROB[j], PROB[j + 1]))
        ctx.model.add_clause((alpha[j], beta[j], -gamma[j], -PROB[j], -PROB[j + 1]))
        ctx.model.add_clause((alpha[j], -beta[j], gamma[j], -PROB[j], -PROB[j + 1]))
        ctx.model.add_clause((alpha[j], -beta[j], -gamma[j], PROB[j], -PROB[j + 1]))
        ctx.model.add_clause((alpha[j], -beta[j], -gamma[j], -PROB[j], PROB[j + 1]))
        ctx.model.add_clause((-alpha[j], beta[j], gamma[j], -PROB[j], -PROB[j + 1]))
        ctx.model.add_clause((-alpha[j], beta[j], -gamma[j], PROB[j], -PROB[j + 1]))
        ctx.model.add_clause((-alpha[j], beta[j], -gamma[j], -PROB[j], PROB[j + 1]))
        ctx.model.add_clause((-alpha[j], -beta[j], gamma[j], PROB[j], -PROB[j + 1]))
        ctx.model.add_clause((-alpha[j], -beta[j], gamma[j], -PROB[j], PROB[j + 1]))
        ctx.model.add_clause((-alpha[j], -beta[j], -gamma[j], PROB[j], PROB[j + 1]))
        ctx.model.add_clause((-alpha[j], -beta[j], -gamma[j], -PROB[j], -PROB[j + 1]))

    for i in range(n):
        ctx.model.add_clause((alpha[i], -gamma[i], PROB[i]))
        ctx.model.add_clause((-alpha[i], gamma[i], PROB[i]))
        ctx.model.add_clause((beta[i], -gamma[i], PROB[i]))
        ctx.model.add_clause((-beta[i], gamma[i], PROB[i]))

        ctx.objective += [(10**ctx.options.sat_precision, PROB[i])]


# *⟨ Parallel ⟩------------------------------------------------------*


"""
ParallelRelation
    same rel
    many wiring
    no internal vars

CompositeRelation
    different rels
    arbitrary wiring
    internal variables
"""


def encode_parallel_sat(rel: ParallelRelation, ctx: SATContext) -> None:
    """Used in:

    AND_CVL
            └── n x WeightedTransitionRelation

    Differential ROT_AND for gcd > 1
        └── g x DifferentialRotAndRelation

    Linear ROT_AND
        └── CompositeRelation
              └── ParallelRelation
                    └── n x WeightedTransitionRelation
    """

    from .core import encode_sat, get_wired_sat_context

    variables = (*ctx.IN, *ctx.OUT)

    for wiring in rel.wiring:
        child_ctx = get_wired_sat_context(rel.rel, variables, wiring, ctx)
        encode_sat(rel.rel, child_ctx)

