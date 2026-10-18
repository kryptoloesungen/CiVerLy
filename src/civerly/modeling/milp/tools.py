import zlib
from dataclasses import dataclass
from itertools import product
from functools import cache
from math import log2
from numbers import Number
from pathlib import Path
from collections.abc import Callable

#
from ... import model_options as MO
from ...component import SBox_CVL, AND_CVL, XOR_CVL

#
from ..tools import _weighted_transition_rel
from ..utils import _get_divide_factor
from ..tools import WeightedTransitions, Bit
from ..tools import ParityEquation

#
from .core import MILPVar, MILPContext

# [ Utilities for _SAT encoding_ of probablistic transitions ]------ *)
#
#
# [ Precomputation ]------------------------------------------------ *)
#
#
# [ # Two-Bit AND ]------------------------------------------------- *)
#
# precomputation for the 2-to-1 bit ANDs (x AND y)


# [ ABG Helper for ModAdd encoding ]-------------------------------- *)
