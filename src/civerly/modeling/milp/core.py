from numbers import Number
from pathlib import Path

#
from sage.numerical.linear_functions import LinearFunction

#
from ...problem import MILP_CVL
from ...component import Component
from ... import model_options as MO

#
from ..core import EncodingContext

# ----------------------------------------------------------------- *)

type MILPVariable = LinearFunction
type MILPObjectiveTerm = tuple[Number, MILPVariable]
type MILPContext = EncodingContext[MILP_CVL, MILPVariable, MILPObjectiveTerm, MO.MODEL_OPTIONS]


# [ Default Context Initialisation Functions ]---------------------- *)


def get_milp_context(
    component: Component,
    options: MO.MODEL_OPTIONS,
) -> MILPContext:

    # hard-coded in the Component._init_model
    model = MILP_CVL(maximization=False)

    # fmt: off
    return EncodingContext(
        model=model,
        IN=model.VAR_IN,    # tuple(model.VAR_IN[i] for i in range(input_width)),
        OUT=model.VAR_OUT,  # tuple(model.VAR_OUT[i] for i in range(output_width)),
        options=options,    # granularity is sort of important here
    )
    # fmt: on


def get_wired_sat_context(
    component: Component,
    parent_variables: tuple[MILPVariable, ...],
    wiring: tuple[int, ...],
    ctx: MILPContext,
) -> MILPContext:
    wired = tuple(parent_variables[i] for i in wiring)
    return EncodingContext(
        model=ctx.model,
        IN=wired[: component.input_length],
        OUT=wired[component.input_length :],
        options=ctx.options,
        objective=ctx.objective,
    )
