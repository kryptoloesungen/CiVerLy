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
from ...utils import bits_to_int
from ...core import EncodingStrategy

#
from ..core import SATContext, SATVar
from ..tools import (
    _encode_xor,
    _parity_three_xor,
    ParityEquation,
    _encode_abg_helper,
    _AND_DIFFERENTIAL_TABLE,
)


# Analysis independent; implemented in modeling.sat.strategy;
# Imported here for "completeness" / as QoL feature
#
# (e.g. I expect civerly.modeling.sat.differential to have defaults for all functions;
#  even if something is analysis independent, I, in theory, do not know this as a user
#  and so I will try to import something like `encode_id` etc. from here. Hence, the extra import
# )
from ..strategy import encode_const_xor, encode_id, encode_permute_layer


# [ Const ]--------------------------------------------------------- *)


def encode_const(component: C_CVL, ctx: SATContext) -> None:
    for variable in ctx.OUT:
        ctx.model.add_clause((-variable,))


# [ XOR ]----------------------------------------------------------- *)


def encode_xor(component: XOR_CVL, ctx: SATContext) -> None:
    _encode_xor(component, ctx, _parity_three_xor)
