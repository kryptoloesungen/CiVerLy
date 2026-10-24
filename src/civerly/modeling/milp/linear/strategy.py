from functools import partial

#
from ....util import translate_sat_clause
from ....component import (
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
from ...tools import bits_to_int, _get_divide_factor, _build_linear_equations
from ...core import EncodingStrategy

#
from ..core import MILPContext, MILPVar
from ..tools import (
    _linear_layer_generalised_wordwise,
    _linear_layer_branch_number,
    _build_linear_matrix,
    _linear_layer_more_dummies,
    _linear_layer_convex_hull,
)


# Analysis independent; implemented in modeling.sat.strategy;
# Imported here for "completeness" / as QoL feature
#
# (e.g. I expect civerly.modeling.sat.differential to have defaults for all functions;
#  even if something is analysis independent, I, in theory, do not know this as a user
#  and so I will try to import something like `encode_id` etc. from here. Hence, the extra import
# )
from ..strategy import (
    encode_const_xor,
    encode_id,
    encode_permute_layer,
)


# [ C_CVL ]--------------------------------------------------------- *)


def encode_const(component: C_CVL, ctx: MILPContext) -> None:
    """The 'do not care' component for linear analysis."""
    return


# [ XOR_CVL ]------------------------------------------------------- *)


def encode_xor(component: XOR_CVL, ctx: MILPContext) -> None:
    divide_by = _get_divide_factor(component, ctx.options)
    n = component.word_length // divide_by

    for i in range(component.word_length // divide_by):
        # Masks for both inputs should be identical
        ctx.model.add_constraint(ctx.IN[i] == ctx.IN[i + n])
        # Output masks should also be the same
        ctx.model.add_constraint(ctx.IN[i] == ctx.OUT[i])


# [ LinearLayer_CVL ]----------------------------------------------- *)


encode_linear_generalised_wordwise = partial(
    _linear_layer_generalised_wordwise,
    _build_linear_matrix,
)

encode_linear_branch_number = partial(_linear_layer_branch_number, "linear")


def encode_linear_more_dummies(component: LinearLayer_CVL, ctx: MILPContext) -> None:
    _linear_layer_more_dummies(component.binary_matrix.transpose(), ctx.OUT, ctx.IN, ctx)
