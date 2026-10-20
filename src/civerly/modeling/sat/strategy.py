from ...component import (
    C_CVL,
    I_CVL,
    XOR_CVL,
    ConstXOR_CVL,
    LinearLayer_CVL,
    PermuteLayer_CVL,
    AND_CVL,
    SBox,
    SBox_CVL,
    ROT_AND_CVL,
)
from ...util import translate_sat_clause

from ..tools import _identity_table, _rotation_table
from ..tools import _wordcoarse_perm_table

#
from .core import SATContext
from .tools import _encode_permutation_sat, _encode_xor_equations, _encode_parity_equation_direct_sat


# ----------------------------------------------------------------- *)


def encode_id(component: I_CVL, ctx: SATContext) -> None:
    _encode_permutation_sat(_identity_table(component.input_length), ctx)


def encode_const_xor(component: ConstXOR_CVL, ctx: SATContext) -> None:
    _encode_permutation_sat(_identity_table(component.input_length), ctx)


def encode_permute_layer(component: PermuteLayer_CVL, ctx: SATContext) -> None:
    wc = component.word_coarseness
    table = _wordcoarse_perm_table(component.perm, wc)
    _encode_permutation_sat(table, ctx)

