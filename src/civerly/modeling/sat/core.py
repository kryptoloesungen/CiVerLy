from numbers import Number
from pathlib import Path

from sage.sat.solvers.dimacs import DIMACS

from ..core import EncodingContext, EncodingStrategy
from ..relation import ComponentRelation

from ...model_options import LINEAR_LAYER_MODELING, MODEL_OPTIONS, SBOX_MODELING
from ..relation import (
    CompositeRelation,
    DifferentialModAddRelation,
    FixedValueRelation,
    LinearModAddRelation,
    ParallelRelation,
    ParityRelation,
    PermutationRelation,
    TrivialRelation,
    WeightedTransitionRelation,
)


# *------------------------------------------------------------------*

SAT_CVL = DIMACS

type SATVar = int
type SATObjectiveTerm = tuple[Number, SATVar]
type SATContext = EncodingContext[SAT_CVL, SATVar, SATObjectiveTerm, MODEL_OPTIONS]



# *⟨ context ⟩-------------------------------------------------------*


def get_sat_context(
    rel: ComponentRelation, options: MODEL_OPTIONS, filename: str | Path | None = None
) -> SATContext:

    model = SAT_CVL(filename=filename) if filename is not None else SAT_CVL()

    return EncodingContext(
        model=model,
        IN=tuple(model.var() for _ in range(rel.input_width)),
        OUT=tuple(model.var() for _ in range(rel.output_width)),
        options=options,
    )


def get_wired_sat_context(
    rel: ComponentRelation,
    variables: tuple[SATVar, ...],
    wiring: tuple[int, ...],
    ctx: SATContext,
) -> SATContext:

    wired = tuple(variables[i] for i in wiring)
    return EncodingContext(
        model=ctx.model,
        IN=wired[: rel.input_width],
        OUT=wired[rel.input_width :],
        options=ctx.options,
        objective=ctx.objective,
    )


# *⟨ encoder resolver ⟩----------------------------------------------*


def get_sat_encoder(
    rel: ComponentRelation, model_options: MODEL_OPTIONS
) -> EncodingStrategy:
    from . import strategy as st

    #    encode_sat(rel, ctx)
    #     |
    #     +-- precomputed SAT model exists?
    #     |       |
    #     |       +-- yes -> instantiate precomputed model
    #     |
    #     +-- no -> get_sat_encoder(rel, options)
    #                 |
    #                 +-- direct
    #                 +-- espresso
    #                 +-- ...

    match rel:
        case PermutationRelation():
            return st.encode_permutation_sat
        case FixedValueRelation():
            return st.encode_fixed_value_sat
        case TrivialRelation():
            return st.encode_trivial_sat

        case ParityRelation():
            if (
                model_options.linear_layer_modeling
                == LINEAR_LAYER_MODELING.MORE_DUMMIES
            ):
                return st.encode_parity_dummies_sat
            return st.encode_parity_direct_sat

        case WeightedTransitionRelation():
            if model_options.sbox_modeling == SBOX_MODELING.LOGICAL_COND_ESPRESSO:
                return st.encode_weighted_transition_espresso_sat
            return st.encode_weighted_transition_direct_sat

        case DifferentialModAddRelation():
            return st.encode_mod_add_differential_sat
        case LinearModAddRelation():
            return st.encode_mod_add_linear_sat

        case ParallelRelation():
            return st.encode_parallel_sat
        case CompositeRelation():
            return st.encode_composite_sat

    from ..util import type_name

    raise NotImplementedError(f"No SAT encoder for {type_name(rel)}")


# [ # Encoding ]---------------------------------------------------- *)


def encode_sat(rel: ComponentRelation, ctx: SATContext) -> None:
    """nil"""
    from .precompute import get_precomputed_sat_model
    from .precompute import encode_precomputed_sat


    # Basically, for now we only have precomputed models for 
    # one specific weighted transition (aka. the one bit AND)
    # so computing anything for it is redundant
    if isinstance(rel, WeightedTransitionRelation):
        precomputed = get_precomputed_sat_model(rel)

        if precomputed is not None:
            encode_precomputed_sat(precomputed, ctx)
            return

    encoder = get_sat_encoder(rel, ctx.options)
    encoder(rel, ctx)
