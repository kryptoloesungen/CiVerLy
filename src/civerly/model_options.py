r"""
Collection of all the available options for modeling.
"""
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class CRYPTANALYSIS(Enum):
    """
    CiVerLy can do differential or linear cryptanalysis.
    """
    DIFFERENTIAL = 1
    LINEAR = 2


class OPTIMIZATION(Enum):
    """
    CiVerLy can either generate MILP or SAT models.
    MILP models can only be generated for objects of ``SBoxCipher`` and its
    subclasses, while SAT models can be generated for objects of any ``Cipher``
    subclass.
    """
    MILP = 1
    SAT = 2


class GRANULARITY(Enum):
    """
    CiVerLy can generate models either on a wordwise or a bitwise level.
    While wordwise models, which require a ``WordSBoxCipher`` or an ``AESlike``
    cipher, are faster to solve, they are less accurate.
    """
    WORDWISE = 1
    BITWISE = 2


class LINEAR_LAYER_MODELING(Enum):
    """
    CiVerLy supports four different techniques to model a linear layer, two
    for wordwise and two for bitwise modeling.

    Wordwise:

    - Modeling based on the branch number: make use of the fact that the number
      of active input and active output words is either zero or at least the
      branch number
    - Generalized wordwise modeling: compute all possible activity patterns for
      the linear layer and model them using the standard convex hull technique

    Bitwise:

    - Convex Hull Technique: model each XOR and then compute the convex hull
    - Technique with more dummies: Again, model each XOR, but introduce dummy
      variables to decrease the number of constraints

    .. NOTE::

        If your implementation does not contain any ``LinearLayer_CVL``
        component, you can set this to ``None``.
    """
    # options for MILP wordwise
    BRANCH_NUMBER = 1
    GENERALIZED_WORDWISE = 2

    # options for MILP bitwise (and SAT)
    CONVEX_HULL = 3
    MORE_DUMMIES = 4

    # options for SAT
    EXCLUDE_ODD = 5


class SBOX_MODELING(Enum):
    """
    CiVerLy supports different techniques for modeling SBoxes.

    - Yu Sasaki and Yosuke Todo: New Algorithm for Modeling S-box in {MILP}
      Based Differential and Division Trail Search
      (https://doi.org/10.1007/978-3-319-69284-5_11)
    - Logical conditioning (https://eprint.iacr.org/2021/213.pdf,
      section 2.3.2) without espresso-reduction
    - Christina Boura and Daniel Coggia: Efficient MILP Modelings for Sboxes
      and Linear Layers of SPN ciphers
      (https://doi.org/10.13154/tosc.v2020.i3.327-361)
    - Logical conditioning (https://eprint.iacr.org/2021/213.pdf,
      section 2.3.2) with espresso-reduction
      (see https://github.com/classabbyamp/espresso-logic)

    .. NOTE::

        If your implementation does not contain any ``SBox_CVL`` component, you
        can set this to ``None``.
    """
    CONVEX_HULL = 1
    LOGICAL_COND = 2
    DISTORTED_BALL = 3
    LOGICAL_COND_ESPRESSO = 4


class SOLVER(Enum):
    """
    The solver to be (automatically) used by CiVerLy. Of course, CiVerLy does
    not implement any solver but simply calls the corresponding solver.

    Supported MILP solvers:

    - SCIP: Open Source and reasonable performance.
    - GLPK: Open Source but only weak performance.
    - Gurobi: Commercial solver (license needed). Best performance.

    Supported SAT solvers:

    - CryptoMiniSat: Open Source solver.
    - CaDiCal: Open Source solver.

    .. NOTE::

        If you are going to solve all models by yourself (e.g. on a different
        machine), you can set this to ``None``.

    .. WARNING::

        Pick a solver only if it is installed on the same machine you are
        running CiVerLy on.
    """
    # MILP solvers
    SCIP = 1
    GLPK = 2
    GUROBI = 3

    # SAT solvers
    CRYPTOMINISAT = 4
    CADICAL = 5


@dataclass(init=True, repr=False)
class MODEL_OPTIONS:
    """
    A dataclass to collect the selected options.

    INPUT:

        - ``cryptanalysis`` -- see
          :class:`civerly.model_options.CRYPTANALYSIS`

        - ``optimization`` -- see
          :class:`civerly.model_options.GRANULARITY`

        - ``linear_layer_modeling`` -- see
          :class:`civerly.model_options.LINEAR_LAYER_MODELING`

        - ``sbox_modeling`` -- see
          :class:`civerly.model_options.SBOX_MODELING`

        - ``solver`` -- see :class:`civerly.model_options.SOLVER`

        - ``solve_range`` -- tuple; The range of weights for which CiVerLy
          should generate models and solve them

        - ``sat_precision`` -- int; The number of decimal places which is used
          to find the optimal SAT-bound

        - ``path`` -- Path; directory where models will be written to

        - ``write_to_file`` -- bool; decides if files are written or not

    Below we show how to use a valid configuration of the model options.

    EXAMPLES::

        sage: from civerly.model_options import *
        sage: from pathlib import Path
        sage: model_options = MODEL_OPTIONS(
        ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:     optimization=OPTIMIZATION.MILP,
        ....:     granularity=GRANULARITY.BITWISE,
        ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.CONVEX_HULL,
        ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
        ....:     solver=SOLVER.SCIP,
        ....:     path=Path("./CiVerLy-Models/"))
        sage: model_options
        MODEL_OPTIONS:
            -> cryptanalysis : DIFFERENTIAL
            -> optimization : MILP
            -> granularity : BITWISE
            -> linear_layer_modeling : CONVEX_HULL
            -> sbox_modeling : CONVEX_HULL
            -> solver : SCIP
            -> solve_range : None
            -> sat_precision : 0
            -> path : CiVerLy-Models
    """
    cryptanalysis: CRYPTANALYSIS
    optimization: OPTIMIZATION
    granularity: GRANULARITY
    linear_layer_modeling: LINEAR_LAYER_MODELING = None
    sbox_modeling: SBOX_MODELING = None
    solver: SOLVER = None
    solve_range: tuple = None
    sat_precision: int = 0
    path: Path = None
    write_to_file: bool = True

    def __repr__(self):
        string = "MODEL_OPTIONS:"
        for attribute, value in self.__dict__.items():
            if isinstance(value, Enum):
                string += f"\n\t-> {attribute} : {value.__dict__['_name_']}"
            elif not isinstance(value, bool):  # skip write_to_file
                string += f"\n\t-> {attribute} : {value}"
        return string

    def __post_init__(self):
        r"""
        This method will be executed right after the implicit __init__ method.
        """
        if self.solve_range is None and self.optimization == OPTIMIZATION.SAT:
            self.solve_range = (0, 100)
        if self.path is None:
            self.write_to_file = False
        self.__validity_check()

    def __validity_check(self):
        """
        Check if ``self`` is consistent. This is executed when initializing
        MODEL_OPTIONS.

        EXAMPLES::

            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.MILP,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.CONVEX_HULL,
            ....:   sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:   solver=SOLVER.SCIP,
            ....:   path=Path("./CiVerLy-Models/"))
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.MILP,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:   sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:   solver=SOLVER.SCIP,
            ....:   path=Path("./CiVerLy-Models/"))
            Traceback (most recent call last):
            ...
            civerly.model_options.InvalidModelOptionException:
            Linear layer modeling must be either None,
            LINEAR_LAYER_MODELING.CONVEX_HULL or
            LINEAR_LAYER_MODELING.MORE_DUMMIES when using bitwise
            MILP modeling.
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis="WRONG_CRYPTANALYSIS",
            ....:   optimization=OPTIMIZATION.MILP,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.CONVEX_HULL,
            ....:   sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:   solver=SOLVER.SCIP,
            ....:   path=Path("./CiVerLy-Models/"))
            Traceback (most recent call last):
            ...
            InvalidModelOptionException: WRONG_CRYPTANALYSIS is an invalid
            attribute for <enum 'CRYPTANALYSIS'>! Only DIFFERENTIAL,
            LINEAR allowed.
        """
        if self.solve_range is not None:
            if self.solve_range[0] < 0 or \
                    self.solve_range[0] >= self.solve_range[1]:
                raise InvalidModelOptionException(
                    self.solve_range,
                    message=f"{self.solve_range} is not valid!"
                )
        if self.sat_precision >= 5:
            raise InvalidModelOptionException(
                f"{self.sat_precision = } is too large. " # noqa
                "Note that the solving complexity grows exponentially "
                "for increased precision parameters."
            )

        # optimization != None
        if self.optimization is None:
            raise InvalidModelOptionException(
                self.optimization,
                message="optimization mode mustn't be None."
            )

        # cryptanalysis != None
        if self.cryptanalysis is None:
            raise InvalidModelOptionException(
                self.cryptanalysis,
                message="cryptanalysis mode mustn't be None."
            )

        # optimization.sat ==> granularity.bitwise
        if self.granularity == GRANULARITY.WORDWISE \
                and self.optimization == OPTIMIZATION.SAT:
            raise InvalidModelOptionException(
                self.granularity,
                message="Wordwise modeling isn't supported for SAT."
            )

        # optimization.milp & granularity.wordwise
        # ==>
        # linear_layer_modeling.{None, branch_number, generalized_wordwise}
        if self.optimization == OPTIMIZATION.MILP \
                and self.granularity == GRANULARITY.WORDWISE \
                and self.linear_layer_modeling not in (
                    None,
                    LINEAR_LAYER_MODELING.BRANCH_NUMBER,
                    LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE
                ):
            raise InvalidModelOptionException(
                self.linear_layer_modeling,
                message="Linear layer modeling must be either None, "
                "LINEAR_LAYER_MODELING.BRANCH_NUMBER or "
                "LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE "
                "when using wordwise modeling."
            )

        # optimization.milp & granularity.bitwise
        # ==>
        # linear_layer_modeling.{None, convex_hull, more_dummies}
        if self.optimization == OPTIMIZATION.MILP \
                and self.granularity == GRANULARITY.BITWISE \
                and self.linear_layer_modeling not in (
                    None,
                    LINEAR_LAYER_MODELING.CONVEX_HULL,
                    LINEAR_LAYER_MODELING.MORE_DUMMIES
                ):
            raise InvalidModelOptionException(
                self.linear_layer_modeling,
                message="Linear layer modeling must be either None, "
                "LINEAR_LAYER_MODELING.CONVEX_HULL or "
                "LINEAR_LAYER_MODELING.MORE_DUMMIES "
                "when using bitwise MILP modeling."
            )

        # optimization.sat
        # ==>
        # linear_layer_modeling.{None, exclude-odd, more-dummies}
        if self.optimization == OPTIMIZATION.SAT \
                and self.linear_layer_modeling not in (
                    None,
                    LINEAR_LAYER_MODELING.EXCLUDE_ODD,
                    LINEAR_LAYER_MODELING.MORE_DUMMIES
                ):
            raise InvalidModelOptionException(
                message="Linear layer modeling must be None, "
                "LINEAR_LAYER_MODELING.SPARSE or "
                "LINEAR_LAYER_MODELING.DENSE"
                "when using SAT modeling."
            )

        # optimization.milp & granularity.wordwise ==> sbox_modeling.None
        if self.optimization == OPTIMIZATION.MILP \
                and self.granularity == GRANULARITY.WORDWISE \
                and self.sbox_modeling is not None:
            raise InvalidModelOptionException(
                self.sbox_modeling,
                message="SBox modeling must be None "
                "when using wordwise modeling."
            )

        # optimization.milp & granularity.bitwise
        # ==>
        # sbox_modeling.{None, convex_hull, logical_cond, logical_cond_espresso, distorted_ball}
        if self.optimization == OPTIMIZATION.MILP \
                and self.granularity == GRANULARITY.BITWISE \
                and self.sbox_modeling not in (
                    None,
                    SBOX_MODELING.CONVEX_HULL,
                    SBOX_MODELING.LOGICAL_COND,
                    SBOX_MODELING.LOGICAL_COND_ESPRESSO,
                    SBOX_MODELING.DISTORTED_BALL,
                ):
            raise InvalidModelOptionException(
                self.sbox_modeling,
                message="SBox modeling must be either None, "
                "SBOX_MODELING.CONVEX_HULL, "
                "SBOX_MODELING.LOGICAL_COND or "
                "SBOX_MODELING.LOGICAL_COND_ESPRESSO or "
                "SBOX_MODELING.DISTORTED_BALL "
                "when using bitwise MILP modeling."
            )

        # optimization.sat
        # ==>
        # sbox_modeling.{None, logical_cond, logical_cond_espresso}
        if self.optimization == OPTIMIZATION.SAT \
                and self.sbox_modeling not in (
                    None,
                    SBOX_MODELING.LOGICAL_COND,
                    SBOX_MODELING.LOGICAL_COND_ESPRESSO,
                ):
            raise InvalidModelOptionException(
                self.sbox_modeling,
                message="SBox modeling must be either None, "
                "SBOX_MODELING.LOGICAL_COND or "
                "SBOX_MODELING.LOGICAL_COND_ESPRESSO "
                "when using SAT modeling."
            )

        # optimization.milp ==> solver.{None, gurobi, scip, glpk}
        if self.optimization == OPTIMIZATION.MILP \
                and self.solver not in (
                    None,
                    SOLVER.GUROBI,
                    SOLVER.SCIP,
                    SOLVER.GLPK
                ):
            raise InvalidModelOptionException(
                self.solver,
                message="Solver modeling must be either None, "
                "SOLVER.GUROBI, "
                "SOLVER.SCIP or "
                "SOLVER.GLPK "
                "when using MILP modeling."
            )

        # optimization.sat ==> solver.{None, cadical, cryptominisat}
        if self.optimization == OPTIMIZATION.SAT \
                and self.solver not in (
                    None,
                    SOLVER.CRYPTOMINISAT,
                    SOLVER.CADICAL
                ):
            raise InvalidModelOptionException(
                self.solver,
                message="Solver modeling must be either None, "
                "SOLVER.CRYPTOMINISAT or "
                "SOLVER.CADICAL "
                "when using MILP modeling."
            )

        # optimization.milp ==> sat_precision.None
        if self.optimization == OPTIMIZATION.MILP \
                and self.sat_precision != 0:
            raise InvalidModelOptionException(
                self.sat_precision,
                message="Sat precision is not unnecessary for "
                "MILP optimization."
            )

        error = False
        if not isinstance(self.cryptanalysis, (CRYPTANALYSIS,)):
            error = True
            attr = self.cryptanalysis
            correct_enum = CRYPTANALYSIS
        elif not isinstance(self.optimization, (OPTIMIZATION,)):
            error = True
            attr = self.optimization
            correct_enum = OPTIMIZATION
        elif not isinstance(self.granularity, (GRANULARITY,)):
            error = True
            attr = self.granularity
            correct_enum = GRANULARITY
        elif not isinstance(
            self.linear_layer_modeling,
            (LINEAR_LAYER_MODELING, type(None))
        ):
            error = True
            attr = self.linear_layer_modeling
            correct_enum = LINEAR_LAYER_MODELING
        elif not isinstance(self.sbox_modeling, (SBOX_MODELING, type(None))):
            error = True
            attr = self.sbox_modeling
            correct_enum = SBOX_MODELING
        elif not isinstance(self.solver, (SOLVER, type(None))):
            error = True
            attr = self.solver
            correct_enum = SOLVER

        if error:
            raise InvalidModelOptionException(
                attr,
                message=f"{attr} is an invalid attribute for {correct_enum}! "
                f"Only {', '.join(correct_enum.__members__.keys())} allowed.")

        return


class NoSolverWarning(Warning):
    r"""
    Warning which will be thrown whenever :meth:`analyse` is called with
    `model_options.solver = None`.

    EXAMPLES::

        sage: from civerly.model_options import *
        sage: from civerly.util import suppress_output
        sage: from civerly.cipher_implementations.aes import AES_CVL
        sage: aes = AES_CVL(6)
        sage: model_options = MODEL_OPTIONS(
        ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:   optimization=OPTIMIZATION.MILP,
        ....:   granularity=GRANULARITY.WORDWISE,
        ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
        ....:   solver=None,
        ....:   path=Path("./DOCTEST-ModelOptions/"))
        sage: with suppress_output():
        ....:   aes.analyse(model_options)
        Traceback (most recent call last):
        ...
        NoSolverWarning: No solver has been selected.
        CiVerLy will return without solving.

        sage: import shutil
        sage: shutil.rmtree("DOCTEST-ModelOptions")


    """
    def __init__(self):
        super().__init__(
            "No solver has been selected. "
            "CiVerLy will return without solving."
        )


class InvalidModelOptionException(Exception):
    r"""
    Exception which will be thrown whenever an invalid model option is given
    by the user.

    TESTS::

        sage: from civerly.model_options import InvalidModelOptionException
        sage: from civerly.model_options import SOLVER
        sage: solver = "WRONG_SOLVER"
        sage: raise InvalidModelOptionException(solver, SOLVER)
        Traceback (most recent call last):
        ...
        InvalidModelOptionException: Invalid solver WRONG_SOLVER!
        sage: solver = "WRONG_SOLVER"
        sage: raise InvalidModelOptionException(
        ....:   solver, message="This solver does not exist."
        ....: )
        Traceback (most recent call last):
        ...
        InvalidModelOptionException: This solver does not exist.


    """
    def __init__(self, model_option, model_option_type=None, message=None):

        self.model_option = model_option
        self.message = message

        if message is None:
            assert model_option_type is not None

            if model_option_type is CRYPTANALYSIS:
                string = "cryptanalysis mode"
            elif model_option_type is OPTIMIZATION:
                string = "optimization mode"
            elif model_option_type is GRANULARITY:
                string = "granularity"
            elif model_option_type is LINEAR_LAYER_MODELING:
                string = "linear layer modeling option"
            elif model_option_type is SBOX_MODELING:
                string = "sbox modeling option"
            elif model_option_type is SOLVER:
                string = "solver"

            message = f"Invalid {string} {model_option}!"

        super().__init__(message)
