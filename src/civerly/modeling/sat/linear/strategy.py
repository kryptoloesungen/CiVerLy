from collections.abc import Callable, Sequence
from types import SimpleNamespace
from functools import partial, cache

#
from ....util import translate_sat_clause
from ....component import (
    Component,
    I_CVL,
    C_CVL,
    ModAdd_CVL,
    ConstXOR_CVL,
    PermuteLayer_CVL,
    XOR_CVL,
    LinearLayer_CVL,
    AND_CVL,
    SBox,
    SBox_CVL,
    ROT_AND_CVL,
)

#
from ...tools import (
    bits_to_int,
    _linear_layer_equations,
    _build_linear_equations,
    _build_differential_equations,
    _get_transition_table_linear,
)
from ...core import EncodingStrategy


#
from ..core import SATContext, get_sat_context, _AND_SBOX
from ..tools import (
    ParityEquation,
    _encode_xor_equations,
    _encode_xor_dummies_linear,
    _encode_linear_layer,
    _parity_equality,
    _encode_abg_helper,
    _weighted_transition_rel,
    _encode_sbox_direct,
    _encode_sbox_espresso,
    _get_espresso_clauses,
    _get_weighted_transition_data,
    _encode_and,
    _precompute_one_bit_and,
)


# Analysis independent; implemented in modeling.sat.strategy;
# Imported here for "completeness" / as QoL feature
#
# (e.g. I expect civerly.modeling.sat.differential to have defaults for all functions;
#  even if something is analysis independent, I, in theory, do not know this as a user
#  and so I will try to import something like `encode_id` etc. from here. Hence, the extra import
# )
from ..strategy import encode_const_xor, encode_id, encode_permute_layer

# [ Utils ]--------------------------------------------------------- *)


# [ C_CVL ]--------------------------------------------------------- *)


def encode_const(component: C_CVL, ctx: SATContext) -> None:

    for variable in ctx.OUT:
        ctx.model.add_clause((-variable, variable))


# [ XOR_CVL ]------------------------------------------------------- *)


def encode_xor(component: XOR_CVL, ctx: SATContext) -> None:
    equations = _parity_equality(component.word_length, ctx.IN, ctx.OUT)
    _encode_xor_equations(ctx, equations)


# [ LinearLayer_CVL ]----------------------------------------------- *)
#
# the goal here is to remove both the Linear vs Differential options
# and to remove Exclude odd vs More dummies options
#
# Since most of the code is the same, right now it is all done with
# a bunch of function call which barely differe from one another,
# so we could think of a better way of implementing it here *shrug*
#


encode_linear_exclude_odd = partial(
    _encode_linear_layer,
    _build_linear_equations,  # build_equations function argument
    _encode_xor_equations,  # encode_equations function argument
)
encode_linear_more_dummies = partial(
    _encode_linear_layer,
    _build_linear_equations,  # build_equations function argument
    _encode_xor_dummies_linear,  # encode_equations function argument
)

# [ SBox_CVL ]------------------------------------------------------ *)

encode_sbox_direct = partial(_encode_sbox_direct, _get_transition_table_linear)
encode_sbox_espresso = partial(_encode_sbox_espresso, _get_transition_table_linear)

# [ AND_CVL ]------------------------------------------------------- *)


# precomputed
@cache
def _get_and_model():
    return _precompute_one_bit_and(*_get_transition_table_linear(_AND_SBOX))


encode_and = partial(_encode_and, _get_and_model)


# [ ModAdd_CVL ]---------------------------------------------------- *)


def encode_mod_add(component: ModAdd_CVL, ctx: SATContext) -> None:
    n = component.word_length
    alpha, beta, gamma, PROB = _encode_abg_helper(ctx, n)

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

    # alpha[j+1] + beta[j+1] + gamma[j+1] + PROB[j+1] + PROB[j+2] == 0
    # for j in range(0, n-2)
    for j in range(1, n - 1):
        # From LinearLayer_CVL:
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

    scale = 10**ctx.options.sat_precision
    for i in range(n):
        ctx.model.add_clause((alpha[i], -gamma[i], PROB[i]))
        ctx.model.add_clause((-alpha[i], gamma[i], PROB[i]))
        ctx.model.add_clause((beta[i], -gamma[i], PROB[i]))
        ctx.model.add_clause((-beta[i], gamma[i], PROB[i]))

        ctx.objective.append((scale, PROB[i]))
