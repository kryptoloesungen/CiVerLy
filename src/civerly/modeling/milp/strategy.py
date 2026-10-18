from ... import model_options as MO
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

from ..utils import _wordcoarse_perm_table, _get_divide_factor
from ..tools import _identity_table, _rotation_table

#
from .core import MILPContext

# [ Bit Permutations ]---------------------------------------------- *)


def _encode_permutation_milp(table: tuple[int], ctx: MILPContext) -> None:
    for i, pi in enumerate(table):
        # note: lhs vs. rhs ordering matters, produces different
        # results if swapped;
        # -> make sure the translation of these parts is literal for
        #    regression testing
        ctx.model.add_constraint(ctx.OUT[pi] == ctx.IN[i])


# ----------------------------------------------------------------- *)


def encode_id(component: I_CVL, ctx: MILPContext) -> None:

    divide_by = _get_divide_factor(component, ctx.options)
    _encode_permutation_milp(_identity_table(component.input_length // divide_by), ctx)


def encode_const_xor(component: ConstXOR_CVL, ctx: MILPContext) -> None:

    divide_by = _get_divide_factor(component, ctx.options)
    _encode_permutation_milp(_identity_table(component.input_length // divide_by), ctx)


def encode_permute_layer(component: PermuteLayer_CVL, ctx: MILPContext) -> None:
    wc = component.word_coarseness
    gran = ctx.options.granularity

    if gran == MO.GRANULARITY.WORDWISE and wc != component.wordsize:
        raise NotImplementedError("Must call the corresponding milp encoder for LinearLayer_CVL.")

    table = (
        _wordcoarse_perm_table(component.perm, wc)
        if gran == MO.GRANULARITY.BITWISE
        else tuple(range(component.input_length // wc))
    )
    _encode_permutation_milp(table)
