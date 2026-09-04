from functools import singledispatch

from ..component import (
    AND_CVL,
    C_CVL,
    I_CVL,
    XOR_CVL,
    Component,
    ConstXOR_CVL,
    LinearLayer_CVL,
    ModAdd_CVL,
    PermuteLayer_CVL,
    SBox_CVL,
)
from ..model_options import CRYPTANALYSIS
from .relation import (
    ComponentRelation,
    DifferentialModAddRelation,
    FixedValueRelation,
    LinearModAddRelation,
    ParallelRelation,
    ParityEquation,
    ParityRelation,
    PermutationRelation,
    TrivialRelation,
    WeightedTransitionRelation,
)
from .util import type_name
from .util import _identity_rel
from .util import AND_DIFFERENTIAL_REL, AND_LINEAR_REL, _weighted_transition_rel


# ----------------------------------------------------------------- *)

# build_rel()
#     knows:
#         Component
#         CRYPTANALYSIS
#
#     does not know:
#         SAT
#         MILP
#         solver args
#         strategy
#
#
# SAT strategy
#     knows:
#         ComponentRelation type
#         solver args through MODEL_OPTIONS
#
#     does not know:
#         Component
#         conflicting analysis semantics
#
# Also, we are using function overloading in python, because I love/hate C[++] too much
# ----------------------------------------------------------------- *)


# *⟨ Docs ⟩----------------------------------------------------------*
# https://docs.python.org/3/glossary.html#term-generic-function
# https://docs.python.org/3/glossary.html#term-single-dispatch


# *⟨ # main ⟩--------------------------------------------------------*
@singledispatch
def build_rel(component: Component, analysis: CRYPTANALYSIS) -> ComponentRelation:
    """nil"""
    raise NotImplementedError(
        f"no rel builder for {type_name(component)} is implemented"
    )


# *⟨ ## Trivial ⟩----------------------------------------------------*


@build_rel.register
def build_identity_rel(
    component: I_CVL, analysis: CRYPTANALYSIS
) -> PermutationRelation:
    """nil"""
    return _identity_rel(component.input_length)


@build_rel.register
def build_const_xor_rel(
    component: ConstXOR_CVL, analysis: CRYPTANALYSIS
) -> PermutationRelation:
    """nil"""
    return _identity_rel(component.input_length)


@build_rel.register
def build_constant_rel(
    component: C_CVL, analysis: CRYPTANALYSIS
) -> FixedValueRelation | TrivialRelation:
    """nil"""
    if analysis == CRYPTANALYSIS.DIFFERENTIAL:
        return FixedValueRelation((0,) * component.output_length)

    return TrivialRelation(0, component.output_length)


# *⟨ ## Permutation / Rotation ⟩-------------------------------------*


@build_rel.register
def build_permutation_rel(
    component: PermuteLayer_CVL, analysis: CRYPTANALYSIS
) -> PermutationRelation:
    """nil"""
    wc = component.word_coarseness

    table = tuple(
        wc * component.perm[i] + j
        for i in range(len(component.perm))
        for j in range(wc)
    )

    return PermutationRelation(table)


# *⟨ ## XOR ⟩--------------------------------------------------------*


@build_rel.register
def build_xor_rel(component: XOR_CVL, analysis: CRYPTANALYSIS) -> ParityRelation:
    """nil"""
    n = component.word_length
    output_offset = 2 * n

    match analysis:
        case CRYPTANALYSIS.DIFFERENTIAL:
            equations = tuple(
                ParityEquation((i, n + i, output_offset + i)) for i in range(n)
            )
        case CRYPTANALYSIS.LINEAR:
            equations = tuple(
                ParityEquation(variables)
                for i in range(n)
                for variables in (
                    (i, output_offset + i),
                    (n + i, output_offset + i),
                )
            )
        case _:
            raise ValueError()

    return ParityRelation(2 * n, n, equations)


# *⟨ ## MOD ⟩--------------------------------------------------------*


@build_rel.register
def build_mod_add_rel(
    component: ModAdd_CVL, analysis: CRYPTANALYSIS
) -> DifferentialModAddRelation | LinearModAddRelation:
    """nil"""
    if analysis == CRYPTANALYSIS.DIFFERENTIAL:
        return DifferentialModAddRelation(component.word_length)

    return LinearModAddRelation(component.word_length)


# *⟨ ## SBox ⟩-------------------------------------------------------*


@build_rel.register
def build_sbox_rel(
    component: SBox_CVL, analysis: CRYPTANALYSIS
) -> WeightedTransitionRelation:
    """nil"""
    table = tuple(map(int, component.S))
    return _weighted_transition_rel(table, analysis)


# *⟨ ## AND ⟩--------------------------------------------------------*


@build_rel.register
def build_and_rel(component: AND_CVL, analysis: CRYPTANALYSIS) -> ParallelRelation:
    """nil"""
    n = component.word_length

    relation = (
        AND_DIFFERENTIAL_REL
        if analysis == CRYPTANALYSIS.DIFFERENTIAL
        else AND_LINEAR_REL
    )

    wiring = tuple((i, n + i, 2 * n + i) for i in range(n))

    return ParallelRelation(relation, 2 * n, n, wiring)


# *⟨ ## LinearLayer ⟩------------------------------------------------*


@build_rel.register
def build_linear_layer_rel(
    component: LinearLayer_CVL, analysis: CRYPTANALYSIS
) -> ParityRelation:
    """nil"""

    # the olde way was to mutate the context, here we just re-index it

    match analysis:
        case CRYPTANALYSIS.DIFFERENTIAL:
            matrix = component.binary_matrix
            source_offset = 0
            target_offset = component.input_length
        case CRYPTANALYSIS.LINEAR:
            matrix = component.binary_matrix.transpose()
            source_offset = component.input_length
            target_offset = 0
        case _:
            raise ValueError()

    equations = tuple(
        ParityEquation(
            (
                *tuple(source_offset + i for i, entry in enumerate(row) if entry == 1),
                target_offset + row_index,
            )
        )
        for row_index, row in enumerate(matrix)
    )

    return ParityRelation(component.input_length, component.output_length, equations)
