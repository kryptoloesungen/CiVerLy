from numbers import Number
from pathlib import Path

from sage.sat.solvers.dimacs import DIMACS

#
from ...component import Component
from ... import model_options as MO

#
from ..core import EncodingContext

# ----------------------------------------------------------------- *)
#
SAT_CVL = DIMACS

type SATVar = int
type SATObjectiveTerm = tuple[Number, SATVar]
type SATContext = EncodingContext[SAT_CVL, SATVar, SATObjectiveTerm, MO.MODEL_OPTIONS]


# [ Default Context Initialisation Functions ]---------------------- *)


def get_sat_context(
    component: Component,
    options: MO.MODEL_OPTIONS,
    filename: str | Path | None = None,
) -> SATContext:

    filename = Path(filename)
    filename.parent.mkdir(parents=True, exist_ok=True)

    model = SAT_CVL(filename=filename) if filename is not None else SAT_CVL()

    return EncodingContext(
        model=model,
        IN=tuple(model.var() for _ in range(component.input_length)),
        OUT=tuple(model.var() for _ in range(component.output_length)),
        options=options,
    )


def get_wired_sat_context(
    component: Component,
    parent_variables: tuple[SATVar, ...],
    wiring: tuple[int, ...],
    ctx: SATContext,
) -> SATContext:
    wired = tuple(parent_variables[i] for i in wiring)
    return EncodingContext(
        model=ctx.model,
        IN=wired[: component.input_length],
        OUT=wired[component.input_length :],
        options=ctx.options,
        objective=ctx.objective,
    )
