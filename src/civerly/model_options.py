r"""
Collection of all the available options for modeling.
"""
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from sage.rings.integer import Integer

from civerly.solvers import SOLVER_CVL, LOGIC_MINIMIZER_CVL
from civerly.solvers import MILP_SOLVER_CVL, SAT_SOLVER_CVL, LOGIC_MINIMIZER_CVL

# Import all solvers, even though they are unused here.
# This way, the user has access to ALL model options
# when importing `civerly.model_options`.
from civerly.solvers import EXTERNAL_MILP_SOLVER_CVL, GUROBI_CVL, SCIP_CVL, GLPK_CVL
from civerly.solvers import EXTERNAL_SAT_SOLVER_CVL, CRYPTOMINISAT_CVL, CADICAL_CVL
from civerly.solvers import NO_LOGIC_MINIMIZER_CVL, ESPRESSO_CVL



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
      section 2.3.2) without Espresso reduction
    - Christina Boura and Daniel Coggia: Efficient MILP Modelings for Sboxes
      and Linear Layers of SPN ciphers
      (https://doi.org/10.13154/tosc.v2020.i3.327-361)
    - Logical conditioning (https://eprint.iacr.org/2021/213.pdf,
      section 2.3.2) with Espresso reduction
      (see https://github.com/classabbyamp/espresso-logic)

    .. NOTE::

        If your implementation does not contain any ``SBox_CVL`` component, you
        can set this to ``None``.
    """
    CONVEX_HULL = 1
    LOGICAL_COND = 2
    DISTORTED_BALL = 3
    LOGICAL_COND_ESPRESSO = 4  # For both MILP / SAT


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

        - ``milp_solver`` -- see :class:`civerly.solvers.MILP_SOLVER_CVL`
        
        - ``sat_solver`` -- see :class:`civerly.solvers.MILP_SOLVER_CVL`

        - ``solve_range`` -- tuple; The range of weights for which CiVerLy
          should generate models and solve them

        - ``sat_precision`` -- int; The number of decimal places which is used
          to find the optimal SAT-bound

        - ``path`` -- Path; directory where models will be written to

        - ``write_to_file`` -- bool; decides if files are written or not

        - ``espresso`` -- bool; decides if Espresso should be used or not

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
        ....:     milp_solver=SCIP_CVL(),
        ....:     path=Path("./CiVerLy-Models/"))
        sage: model_options
        MODEL_OPTIONS:
            -> cryptanalysis : DIFFERENTIAL
            -> optimization : MILP
            -> granularity : BITWISE
            -> linear_layer_modeling : CONVEX_HULL
            -> sbox_modeling : CONVEX_HULL
            -> milp_solver : <class 'civerly.solvers.SCIP_CVL'>
            -> sat_solver : <class 'civerly.solvers.EXTERNAL_SAT_SOLVER_CVL'>
            -> logic_minimizer : <class 'civerly.solvers.NO_LOGIC_MINIMIZER_CVL'>
            -> solve_range : None
            -> sat_precision : 0
            -> number_of_solutions : 1
            -> path : CiVerLy-Models
        sage: model_options = MODEL_OPTIONS(
        ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:     optimization=OPTIMIZATION.MILP,
        ....:     granularity=GRANULARITY.BITWISE,
        ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.CONVEX_HULL,
        ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
        ....:     milp_solver=None,
        ....:     path=Path("./CiVerLy-Models/"))
        sage: model_options
        MODEL_OPTIONS:
            -> cryptanalysis : DIFFERENTIAL
            -> optimization : MILP
            -> granularity : BITWISE
            -> linear_layer_modeling : CONVEX_HULL
            -> sbox_modeling : CONVEX_HULL
            -> milp_solver : <class 'civerly.solvers.EXTERNAL_MILP_SOLVER_CVL'>
            -> sat_solver : <class 'civerly.solvers.EXTERNAL_SAT_SOLVER_CVL'>
            -> logic_minimizer : <class 'civerly.solvers.NO_LOGIC_MINIMIZER_CVL'>
            -> solve_range : None
            -> sat_precision : 0
            -> number_of_solutions : 1
            -> path : CiVerLy-Models
    """

    # specify types and default values
    cryptanalysis: CRYPTANALYSIS = None
    optimization: OPTIMIZATION = None
    granularity: GRANULARITY = None
    linear_layer_modeling: LINEAR_LAYER_MODELING = None
    sbox_modeling: SBOX_MODELING = None
    milp_solver: MILP_SOLVER_CVL = None
    sat_solver: SAT_SOLVER_CVL = None
    logic_minimizer: LOGIC_MINIMIZER_CVL = None
    solve_range: tuple = None
    sat_precision: int = 0
    number_of_solutions: int = 1
    path: Path = None
    write_to_file: bool = True

    def __repr__(self):
        string = "MODEL_OPTIONS:"
        for attribute, value in self.__dict__.items():
            if isinstance(value, Enum):
                string += f"\n\t-> {attribute} : {value.__dict__['_name_']}"
            elif isinstance(value, SOLVER_CVL):
                string += f"\n\t-> {attribute} : {type(value)}"
            elif not isinstance(value, bool):  # skip write_to_file
                string += f"\n\t-> {attribute} : {value}"
        return string

    def __post_init__(self):
        r"""
        This method will be executed right after the implicit __init__ method.
        """
        # set self.{milp, sat}_solver to respective NoneSolver
        if self.milp_solver is None:
            self.milp_solver = EXTERNAL_MILP_SOLVER_CVL()
        
        if self.sat_solver is None:
            self.sat_solver = EXTERNAL_SAT_SOLVER_CVL()
        
        if self.logic_minimizer is None:
            self.logic_minimizer = NO_LOGIC_MINIMIZER_CVL()
        
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
            ....:   milp_solver=SCIP_CVL(),
            ....:   path=Path("./CiVerLy-Models/"))
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.MILP,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:   sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:   milp_solver=SCIP_CVL(),
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
            ....:   milp_solver=SCIP_CVL(),
            ....:   path=Path("./CiVerLy-Models/"))
            Traceback (most recent call last):
            ...
            InvalidModelOptionException: WRONG_CRYPTANALYSIS is an invalid
            attribute for <enum 'CRYPTANALYSIS'>! Only DIFFERENTIAL,
            LINEAR allowed.
        """
        if not isinstance(self.number_of_solutions, (int, Integer)) \
                or self.number_of_solutions < 1:
            raise InvalidModelOptionException(
                self.number_of_solutions,
                message=(
                    "number_of_solutions must be a positive integer, "
                    f"got {self.number_of_solutions!r}."
                )
            )

        if self.solve_range is not None:
            if self.solve_range[0] < 0 or \
                    self.solve_range[0] > self.solve_range[1]:
                raise InvalidModelOptionException(
                    self.solve_range,
                    message=f"solve_range = {self.solve_range} is not valid!"
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
        # sbox_modeling.{None, convex_hull, logical_cond,
        # logical_cond_espresso, distorted_ball}
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

        # milp_solver.{None, gurobi, scip, glpk}
        if not isinstance(self.milp_solver, MILP_SOLVER_CVL):
            raise InvalidModelOptionException(
                self.milp_solver,
                message="Solver modeling must be either None, "
                "Gurobi, "
                "Scip or "
                "Glpk "
                "when using MILP modeling."
            )

        # sat_solver.{None, cadical, cryptominisat}
        if not isinstance(self.sat_solver, SAT_SOLVER_CVL):
            raise InvalidModelOptionException(
                self.sat_solver,
                message="Solver must be either None, "
                "CryptoMiniSat or "
                "CaDiCal "
                "when using SAT modeling."
            )

        # optimization.milp ==> sat_precision.None
        if self.optimization == OPTIMIZATION.MILP \
                and self.sat_precision != 0:
            raise InvalidModelOptionException(
                self.sat_precision,
                message="Sat precision is unnecessary for "
                "MILP optimization."
            )

        if not isinstance(self.logic_minimizer, LOGIC_MINIMIZER_CVL):
            raise InvalidModelOptionException(
                self.logic_minimizer,
                message="logic_minimizer must be either NO_LOGIC_MINIMIZER_CVL or "
                "ESPRESSO_CVL."
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

        if error:
            raise InvalidModelOptionException(
                attr,
                message=f"{attr} is an invalid attribute for {correct_enum}! "
                f"Only {', '.join(correct_enum.__members__.keys())} allowed.")

        return


class InvalidModelOptionException(Exception):
    r"""
    Exception which will be thrown whenever an invalid model option is given
    by the user.

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
            # elif model_option_type is MILP_SOLVER_CVL:
            #     string = "milp_solver"
            # elif model_option_type is SAT_SOLVER_CVL:
            #     string = "sat_solver"
            # elif model_option_type is LOGIC_MINIMIZER_CVL:
            #     string = "logic_minimizer"

            message = f"Invalid {string} {model_option}!"

        super().__init__(message)
