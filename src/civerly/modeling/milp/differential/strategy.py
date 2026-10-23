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
from ...tools import (
    bits_to_int,
    _get_divide_factor,
    _build_differential_equations,
    _build_linear_equations,
)
from ...core import EncodingStrategy

#
from ..core import MILPContext, MILPVar
from ..tools import (
    _linear_layer_generalised_wordwise,
    _build_differential_matrix,
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
    divide_by = _get_divide_factor(component, ctx.options)
    for i in range(component.output_length // divide_by):
        ctx.model.add_constraint(ctx.OUT[i] == 0)


# [ XOR_CVL ]------------------------------------------------------- *)


def encode_xor(component: XOR_CVL, ctx: MILPContext) -> None:
    divide_by = _get_divide_factor(component, ctx.options)
    n = component.word_length // divide_by

    #
    _extra_eq = ((1, 1, 1), -2) if divide_by == 1 else ()
    #
    assignments_rhs = (
        ((1, 0, 0), 0),
        ((0, 1, 0), 0),
        ((0, 0, 1), 0),
    ) + _extra_eq

    for i in range(component.word_length // divide_by):
        variables = (ctx.IN[i], ctx.IN[i + n], ctx.OUT[i])

        for assignment, rhs in assignments_rhs:
            ctx.model.add_constraint(
                sum(-var if value else var for var, value in zip(variables, assignment)) >= rhs
            )


# [ LinearLayer_CVL ]----------------------------------------------- *)


encode_linear_generalised_wordwise = partial(
    _linear_layer_generalised_wordwise,
    _build_differential_matrix
)
