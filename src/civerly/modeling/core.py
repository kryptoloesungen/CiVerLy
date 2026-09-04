from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Generic, TypeVar

from .relation import ComponentRelation

# *------------------------------------------------------------------*

ModelT = TypeVar("ModelT")
VarT = TypeVar("VarT")
ObjectiveTermT = TypeVar("ObjectiveTermT")
OptionsT = TypeVar("OptionsT") # idk, in case we want to allow some more options / user options


# [ context ]------------------------------------------------------- *)
@dataclass(slots=True)
class EncodingContext(Generic[ModelT, VarT, ObjectiveTermT, OptionsT]):
    """Mutable state used for encoding a component"""

    model: ModelT
    IN: tuple[VarT, ...]
    OUT: tuple[VarT, ...]
    # usually something like `model_options`
    options: OptionsT
    objective: list[ObjectiveTermT] = field(default_factory=list)


# [ encoding ]------------------------------------------------------ *)
type EncodingStrategy = Callable[[ComponentRelation, EncodingContext], None]
