from collections.abc import Callable

#
from ....util import translate_sat_clause
from ....component import (
    Component,
    I_CVL,
    C_CVL,
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
from ...tools import bits_to_int
from ...core import EncodingStrategy

#
from ..core import SATContext, SATVar
from ..tools import (
    ParityEquation,
    _encode_xor_equations,
    _parity_equality,
    _two_bit_xor_linear,
    _linear_layer_equations,
    _encode_linear_layer_exclude_odd,
    _encode_linear_layer_more_dummies,
    _encode_abg_helper,
    _AND_LINEAR_TABLE,
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
    equations = _parity_equality(component.word_length)
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


def _encode_linear_layer(component: LinearLayer_CVL, ctx: SATContext) -> None:
    matrix = component.binary_matrix.transpose()
    IN = ctx.OUT
    OUT = ctx.IN

    equations = _linear_layer_equations(matrix, IN, OUT)
    two_bit_xor_f = _two_bit_xor_linear

    return equations, two_bit_xor_f


def encode_linear_layer_exclude_odd(component: LinearLayer_CVL, ctx: SATContext) -> None:
    _encode_linear_layer_exclude_odd(component, ctx, _encode_linear_layer)


def encode_linear_layer_more_dummies(component: LinearLayer_CVL, ctx: SATContext) -> None:
    _encode_linear_layer_more_dummies(component, ctx, _encode_linear_layer)
