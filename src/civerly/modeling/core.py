from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Generic, TypeVar, TYPE_CHECKING

from functools import singledispatch

#
from .tools import type_name

#
if TYPE_CHECKING:
    from ..component import Component
    from ..model_options import MODEL_OPTIONS

# [ Types ]--------------------------------------------------------- *)

ModelT = TypeVar("ModelT")
VarT = TypeVar("VarT")
ObjectiveTermT = TypeVar("ObjectiveTermT")
OptionsT = TypeVar("OptionsT")  # idk, in case we want to allow some more options / user options


# [ context ]------------------------------------------------------- *)


@dataclass(slots=True)
class EncodingContext(Generic[ModelT, VarT, ObjectiveTermT, OptionsT]):
    """Mutable state used for encoding a component"""

    # the encoding
    model: ModelT

    # variables
    IN: tuple[VarT, ...]
    OUT: tuple[VarT, ...]

    # `model_options` for some internal parameters passed to the solvers
    # which are not yet saved here
    options: OptionsT

    # replaces `sum_arr_{sat,milp}`
    objective: list[ObjectiveTermT] = field(default_factory=list)


# [ encoding ]------------------------------------------------------ *)

# type for a function provided by the user;
# takes as input a component + context,
# mutates the context writing the constraints + objective into it
type EncodingStrategy = Callable[[Component, EncodingContext], None]


@singledispatch
def encode(component: Component, ctx: EncodingContext):
    r"""
    """
    raise NotImplementedError(f"no encoder defined for {type_name(component)}.")
    


