from __future__ import annotations

from dataclasses import dataclass
# ----------------------------------------------------------------- *)


# See the end of the file for some ruminations of a sleep-deprived caffeine addict


# [ vocab ]--------------------------------------------------------- *)
# OUT, IN : output / input variable vectors
#
# variable namespace: which indices we use to define the vars.
# we typically write them as
#          (*IN, *OUT) <=> [IN,...,OUT,...]
#
# ----------------------------------------------------------------- *)

# using `Bit` instead of just int to indicate that we are expecting 0/1
Bit = int

# [ trivial relations ]--------------------------------------------- *)


@dataclass(frozen=True, slots=True)
class PermutationRelation:
    """stores the table we use to get vars in a permutations relation"""

    # OUT[table[i]] = IN[i]
    table: tuple[int, ...]

    # implicit width:
    #     input_width  = len(table)
    #     output_width = len(table)

    @property
    def input_width(self) -> int:
        return len(self.table)

    @property
    def output_width(self) -> int:
        return len(self.table)


# ----------------------------------------------------------------- *)


@dataclass(frozen=True, slots=True)
class FixedValueRelation:
    """eq. of vars with respect to some value."""

    # OUT[i] = output_value[i]
    # fixed bit-vector that OUT must equal.
    output_value: tuple[Bit, ...]

    # no inputs for constants
    input_width: int = 0

    @property
    def output_width(self) -> int:
        return len(self.output_value)


# ----------------------------------------------------------------- *)


@dataclass(frozen=True, slots=True)
class TrivialRelation:
    """encodes `True`, i.e. we do not need to add anything"""

    input_width: int = 0
    output_width: int = 0


# [ generic relations ]--------------------------------------------- *)


@dataclass(frozen=True, slots=True)
class ParityEquation:
    """indices of all variables in one XOR equation

    flat local namespace:
        [IN..., OUT...] = [0, ... , |IN| - 1, |IN|, ... , |OUT| - 1]

    Example:
        variables = (0, 2, 5)

    means:
        VAR[0] XOR VAR[2] XOR VAR[5] = rhs
    """

    variables: tuple[int, ...]

    # right hand side
    rhs: Bit = 0


@dataclass(frozen=True, slots=True)
class ParityRelation:
    """system of parity equations

    semantics: conjunction of equations over GF(2)

    Example:
    Operation: XOR

    IN  = (a, b)
    OUT = (c,)

    index:     0  1  2
    variable:  a  b  c
            |
            v

    ParityRelation(
        input_width=2,
        output_width=1,
        equations=[ ParityEquation(variables=(0, 1, 2)) ]
    )

    i.e. : var0 xor var1 xor var2 = 0 <=> var2 = var1 xor var0

    direct SAT encoding of this thing will then later used to produce an encoding:
         a OR  b OR -c
         a OR -b OR  c
        -a OR  b OR  c
        -a OR -b OR -c


    Encoding:
    - either `direct`,
    - or `more dummies`

    .
    """

    input_width: int
    output_width: int
    equations: tuple[ParityEquation, ...]


# One bit XOR:
# rel = ParityRelation(
#     input_width=2*1,
#     output_width=1,
#     equations=(
#         ParityEquation((0, 1, 2)),
#     ),
# )
#
# This one is for n bits:
# rel = ParityRelation(
#     input_width=2 * n,
#     output_width=n,
#     equations=tuple(
#         ParityEquation((i, n + i, (2*n) + i)) <=> v(i) + v(n + i) + v(2n + i)
#         for i in range(n)
#     )
# )
#
# This here is for the linear: a = c and b = c
# rel = ParityRelation(
#     input_width=2*n,
#     output_width=n,
#     # could also use itertools.chain.from_iterable here
#     equations=tuple(
#         equation
#         for i in range(n)
#             for equation in (
#                 ParityEquation((i, 2 * n + i)),
#                 ParityEquation((n + i, 2 * n + i)),
#             )
#     ),
# )


# [ transitions with weights / probabilistic transitions ]---------- *)
# (e.g. non-linear elements)


@dataclass(frozen=True, slots=True)
class WeightedTransition:
    """One allowed input/output assignment

    same flat namespace:
        [IN..., OUT...]
    """

    bits: tuple[Bit, ...]
    # Example for a 2 -> 1 relation:
    #     bits = (1, 0, 1) -> read (1, 0) -> (1,)

    metric: int
    # weight associated with the transition
    #
    # using 'metric' (weight, probability, correlation), although it should probs be 'weight'


@dataclass(frozen=True, slots=True)
class WeightedTransitionRelation:
    input_width: int
    output_width: int
    # All permitted input/output transitions, together with their metrics.
    transitions: tuple[WeightedTransition, ...]

    # normaliser / scaler used to convert transition metrics into objective weights
    #
    # typical expression everywhere:
    #     weight = -log2(metric / normaliser)
    #
    # e.g. for n-bit S-Box is 2^n
    normalizer: int


# [ non-genericl relations ]---------------------------------------- *)

# [ # modular addition ]-------------------------------------------- *)


@dataclass(frozen=True, slots=True)
class DifferentialModAddRelation:
    width: int

    @property
    def input_width(self) -> int:
        return 2 * self.width

    @property
    def output_width(self) -> int:
        return self.width


@dataclass(frozen=True, slots=True)
class LinearModAddRelation:
    width: int

    @property
    def input_width(self) -> int:
        return 2 * self.width

    @property
    def output_width(self) -> int:
        return self.width


# [ # Rotate-AND ]-------------------------------------------------- *)


@dataclass(frozen=True, slots=True)
class DifferentialRotAndRelation:
    """
    i, i + rotation, i + 2*rotation modulo width

    will actually trigger encode_rot_and_* when gcd(width, rotation)
    """

    width: int
    rotation: int

    @property
    def input_width(self) -> int:
        return self.width

    @property
    def output_width(self) -> int:
        return self.width


# [ structural relations / glue ]----------------------------------- *)


@dataclass(frozen=True, slots=True)
class RelationWiring:
    """used to wire the local variables to global variables."""

    rel: ComponentRelation
    # relation to be wired

    variables: tuple[int, ...]
    # in CompositeRelation namespace:
    #     [IN..., OUT ..., AUX...]
    #
    # child local variable namespace:
    #     [this IN..., this OUT]
    #
    # for child local k
    # variables[k] := var in CompositeRelation


@dataclass(frozen=True, slots=True)
class ParallelRelation:
    """idea: repeated copies of one rel. + allow to re-wire on output"""

    rel: ComponentRelation
    # rel to be repeated

    input_width: int
    output_width: int

    wiring: tuple[tuple[int, ...], ...]
    # a tuple wiring[i] represents the wiring for component i
    #
    # global namespace: [IN..., OUT...]
    #
    # wiring[i][k] := where the components i variable k goes in the global namespace


# ----------------------------------------------------------------- *)


@dataclass(frozen=True, slots=True)
class CompositeRelation:
    input_width: int
    # #external input variables

    output_width: int
    # #external output variables

    internal_width: int
    # #external aux variables used by children

    parts: tuple[RelationWiring, ...]
    # Child relations making up the composition.
    #
    # part gives:
    #     - which relation is used
    #     - the variable mapping
    #
    # common global variable namespace is:
    #     [IN..., OUT..., AUX...]


# ----------------------------------------------------------------- *)

type AtomicRelation = (
    PermutationRelation
    | FixedValueRelation
    | TrivialRelation
    | ParityRelation
    | WeightedTransitionRelation
    | DifferentialModAddRelation
    | LinearModAddRelation
    | DifferentialRotAndRelation
)

type ComponentRelation = AtomicRelation | ParallelRelation | CompositeRelation
