r"""
Utils for interacting with MILP and SAT solvers.
"""

import re
import json
import subprocess
import os
import warnings
import time
from pathlib import Path
from enum import Enum

from civerly.util import suppress_output, _float_or_int
from civerly.util import _to_dict

from abc import ABC, abstractmethod


class SOLVING_STATUS(Enum):
    """Indicate if solving was successful or what went wrong."""

    SUCCESS = 1
    TIMEOUT = 2
    ERROR = 3


class NoSolverWarning(Warning):
    r"""
    Warning which will be thrown whenever :meth:`analyse` is called with
    `model_options.solver = None`.

    EXAMPLES::

        sage: from civerly.model_options import *
        sage: from civerly.util import suppress_output
        sage: from civerly.cipher_implementations.aes import AES_CVL
        sage: import tempfile
        sage: aes = AES_CVL(6)
        sage: with tempfile.TemporaryDirectory() as tmpdir:
        ....:   model_options = MODEL_OPTIONS(
        ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:     optimization=OPTIMIZATION.MILP,
        ....:     granularity=GRANULARITY.WORDWISE,
        ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
        ....:     milp_solver=None,
        ....:     sat_solver=None,
        ....:     path=Path(tmpdir))
        ....:   with suppress_output():
        ....:     aes.analyse(model_options)
        Traceback (most recent call last):
        ...
        NoSolverWarning: No solver has been selected.
        CiVerLy will return without solving.
    """
    def __init__(self):
        super().__init__(
            "No solver has been selected. "
            "CiVerLy will return without solving."
        )


class SOLVER_CVL(ABC):
    """
    Abstract base class for implementing an interface to a solver.
    """
    def __init__(self):
        """
        Initialize the solver interface.

        Subclasses must set ``self.name``. They may also adjust
        ``self.errno_map`` and ``self.store_stdout`` to configure how the
        shared :meth:`invoke` template interprets the solver's behavior.
        """
        self.name = "GenericSolver"
        self.can_solve_multiple = False
        # exit-code -> SOLVING_STATUS. Unknown codes default to ERROR.
        self.errno_map = {0: SOLVING_STATUS.SUCCESS}
        # If True, ``invoke`` redirects subprocess stdout/stderr into ``log_file``.
        # Solvers that write their own log via CLI flags leave this False.
        self.store_stdout = False

    @abstractmethod
    def solve(self, input_file, time_limit=None):
        """
        Solve the model in the given file.

        INPUT:

            - ``input_file`` -- path to the file containing the model

            - ``time_limit`` -- float or ``None`` (default ``None``); time limit in seconds

        OUTPUT:

            - ``result`` -- a dictionary with at least the following entries:

                - ``status`` -- see :class:`civerly.solvers.SOLVING_STATUS`
                - ``assingment`` -- dictionary or ``None``; the assignment of the variables in the solution
                - ``solve_time`` -- float; time (in seconds) it took to find this solution

        .. Warning::

            If ``time_limit`` is reached, the solution might be non-optimal.
        """
        pass

    def solve_multiple(self, input_file, number_of_solutions, time_limit=None):
        r"""
        Find the ``number_of_solutions`` best solutions to the model.

        This method is optional and only implemented for solvers that have corresponding functionality.
        When implemented ``self.can_solve_multiple`` shall be set to ``True``.

        INPUT:

            - ``input_file`` -- path to the file containing the model

            - ``number_of_solutions`` -- number of solutions to find

            - ``time_limit`` -- float or ``None`` (default ``None``); time limit in seconds

        OUTPUT:

            - ``results`` -- a list of at most ``number_of_solutions`` many ``result``, see :meth:`.solve`.
              If there are less solutions ``results`` may be shorter. ``results`` is ordered; best is at ``results[0]``.
        """
        raise NotImplementedError


    def _check_can_invoke(self, input_file, solution_file, log_file):
        """
        Verify the inputs and honor the ``CIVERLY_DISABLE_<NAME>`` env override.

        This is called by :meth:`invoke` and is also exposed for subclasses
        that override :meth:`invoke` entirely and still need the standard
        precondition checks.
        """
        assert isinstance(input_file, Path)
        assert isinstance(solution_file, Path)
        assert isinstance(log_file, Path)

        # you can disable a solver by setting an environment variable
        # with this we simulate that a solver is not installed albeit it is
        # i.e. this is used for testing only
        ENV_DISABLE_PREFIX = "CIVERLY_DISABLE_"
        if ENV_DISABLE_PREFIX+self.name.upper() in os.environ:
            raise ValueError(
                f"{self.name} was disabled by setting environment variable "
                f"{ENV_DISABLE_PREFIX+self.name.upper()}"
            )

    def invoke(self, input_file, solution_file, log_file, time_limit=None):
        """
        Invoke the solver's CLI to solve the model in the given file.

        This template handles the env-disable check, command execution
        (optionally capturing stdout/stderr into ``log_file``), and exit-code
        interpretation. Subclasses provide the command list via
        :meth:`_build_command`, and may adjust ``self.errno_map`` or
        ``self.store_stdout`` to tailor the behavior.

        INPUT:

            - ``input_file``-- path to the file containing the model

            - ``solution_file``-- path of the file in which the solver writes the solution

            - ``log_file``-- path to the solver's log file

            - ``time_limit``-- float (default ``None``); time limit in seconds

        OUTPUT:

            - Status, see :class:`civerly.solvers.SOLVING_STATUS`. Further, upon
              successful execution a solution is stored in ``solution_file``.
        """
        self._check_can_invoke(input_file, solution_file, log_file)
        command = self._build_command(input_file, solution_file, log_file, time_limit)
        if self.store_stdout:
            with log_file.open('a') as redirect, suppress_output():
                errno = subprocess.Popen(
                    command, stdout=redirect, stderr=redirect
                ).wait()
        else:
            with suppress_output():
                errno = subprocess.Popen(command).wait()
        return self.errno_map.get(errno, SOLVING_STATUS.ERROR)

    @abstractmethod
    def _build_command(self, input_file, solution_file, log_file, time_limit):
        """
        Build the solver-specific CLI command list.

        INPUT:

            - ``input_file`` -- path to the file containing the model
            - ``solution_file`` -- path of the file in which the solver writes the solution
            - ``log_file`` -- path to the solver's log file
            - ``time_limit`` -- float or ``None``; time limit in seconds

        OUTPUT:

            - list of strings; the command to be passed to ``subprocess.Popen``
        """
        pass


class MILP_SOLVER_CVL(SOLVER_CVL, ABC):
    """Abstract base class for implementing an interface to a MILP solver."""

    def __init__(self):
        """Initizialize the MILP solver interface."""
        super().__init__()

    def invoke(self, input_file, solution_file, log_file, time_limit=None):
        """
        Invoke the MILP solver, wrapping the shared template with a
        log-file-based timeout check.

        .. SEEALSO::

            :meth:`civerly.solvers.SOLVER_CVL.invoke`
        """
        status = super().invoke(input_file, solution_file, log_file, time_limit)
        return self._check_timeout(log_file, time_limit, status)

    def solve(self, input_file, time_limit=None):
        """
        Solve the model in the given file.

        INPUT:

            - ``input_file`` -- path to the file containing the model

            - ``time_limit`` -- float or ``None`` (default ``None``); time limit in seconds

        OUTPUT:

            - ``result`` -- a dictionary with at least the following entries:

                - ``status`` -- see :class:`civerly.solvers.SOLVING_STATUS`
                - ``objective_value`` -- float; the objective value of the identified solution
                - ``objective_bounds`` -- tuple of floats; lower and upper bound for the optimal objective value (interesting when ``time_limit`` is reached)
                - ``assingment`` -- dictionary; the assignment of the variables in the solution
                - ``solve_time`` -- float; time (in seconds) it took to find this solution

        .. Warning::

            If ``time_limit`` is reached, the solution might be non-optimal.
        """
        start_time = time.perf_counter()
        solution_file = input_file.parent / f"{input_file.stem}_{self.name}.sol"
        log_file = input_file.parent / f"{input_file.stem}_{self.name}.log"
        status = self.invoke(input_file, solution_file, log_file, time_limit=time_limit)
        solve_time = time.perf_counter() - start_time

        if status == SOLVING_STATUS.SUCCESS:
            objective_value, assignment = self._process_solution_file(solution_file)
            objective_bounds = (objective_value, objective_value)
        elif status == SOLVING_STATUS.TIMEOUT:
            objective_value, assignment = self._process_solution_file(solution_file)
            objective_bounds = self._get_objective_bounds(log_file)
        else:
            objective_value = None
            assignment = {}
            objective_bounds = (None, None)

        result = {"status": status, "objective_value": objective_value, "objective_bounds": objective_bounds, "assingment": assignment, "solve_time": solve_time}
        return result

    def _get_objective_bounds(self, log_file):
        """
        Extract the bounds on the objective value from the log of an MILP solver.

        This function is used when the MILP solver exceeds the given timeout.
        It searches ``log_file`` for ``self.bounds_regexp`` and expects two
        groups: group 1 is the upper bound, group 2 is the lower bound.

        INPUT:

            - ``log_file``-- name of the log file

        OUTPUT:

            - tuple of floats; lower and upper bound for the optimal objective value
        """
        assert isinstance(log_file, Path)

        with log_file.open('r') as file:
            content = file.read()

        hit = re.search(self.bounds_regexp, content, re.MULTILINE)
        if hit:
            upper_bound = _float_or_int(hit.group(1))
            lower_bound = _float_or_int(hit.group(2))
            return lower_bound, upper_bound

        warnings.warn(f"No objective bounds found in {log_file}")
        return None, None

    def _check_timeout(self, log_file, time_limit, status):
        """
        Check the log file for a timeout report and update ``status`` accordingly.

        If ``time_limit`` is ``None`` the status is returned unchanged.
        Otherwise ``log_file`` is searched for ``self.timeout_string`` and
        ``SOLVING_STATUS.TIMEOUT`` is returned on a hit.

        INPUT:

            - ``log_file`` -- path to the log file
            - ``time_limit`` -- float or ``None``; the time limit passed to the solver
            - ``status`` -- the current :class:`SOLVING_STATUS`

        OUTPUT:

            - the (possibly updated) :class:`SOLVING_STATUS`
        """
        if time_limit is None:
            return status
        with log_file.open('r') as file:
            content = file.read()
        if re.search(self.timeout_string, content, re.MULTILINE):
            return SOLVING_STATUS.TIMEOUT
        return status

    @abstractmethod
    def _process_solution_file(self, solution_file):
        """
        Extract the objective value and the variable assignment of the solution.

        INPUT:

            - ``solution_file``-- path to the file containing the solution

        OUTPUT:

            - ``objective_value`` -- float; the objective value of the solution

            - ``assingment`` -- dictionary; the assignment of the variables in the solution
        """
        pass


class SAT_SOLVER_CVL(SOLVER_CVL, ABC):
    """Abstract base class for implementing an interface to a SAT solver."""

    def __init__(self):
        """Initizialize the SAT solver interface."""
        super().__init__()
        # 10 = SAT, 20 = UNSAT are standard DIMACS exit codes.
        self.errno_map = {
            0: SOLVING_STATUS.SUCCESS,
            10: SOLVING_STATUS.SUCCESS,
            20: SOLVING_STATUS.SUCCESS,
        }
        # SAT solvers print results to stdout; capture into the log file.
        self.store_stdout = True

    def solve(self, input_file, time_limit=None):
        """
        Solve the model in the given file.

        INPUT:

            - ``input_file`` -- path to the file containing the model

            - ``time_limit`` -- float or ``None`` (default ``None``); time limit in seconds

        OUTPUT:

            - ``result`` -- a dictionary with at least the following entries:

                - ``status`` -- see :class:`civerly.solvers.SOLVING_STATUS`
                - ``satisfiability`` -- bool or ``None``
                - ``assingment`` -- dictionary; the assignment of the variables in the solution
                - ``solve_time`` -- float; time (in seconds) it took to find this solution
        """
        start_time = time.perf_counter()
        solution_file = input_file.parent / f"{input_file.stem}_{self.name}.sat"
        log_file = input_file.parent / f"{input_file.stem}_{self.name}.log"
        status = self.invoke(input_file, solution_file, log_file, time_limit=time_limit)
        solve_time = time.perf_counter() - start_time

        if status == SOLVING_STATUS.SUCCESS:
            satisfiability, assignment = self._process_solution_file(solution_file)
        else:
            satisfiability = None
            assignment = {}

        result = {"status": status, "satisfiability": satisfiability, "assingment": assignment, "solve_time": solve_time}
        return result

    def _parse_assignment_line(self, line):
        """
        Parse a DIMACS-style assignment line into a ``{var: 0/1}`` dictionary.

        The line is expected to be a space-separated list of signed integers
        terminated by a ``0`` sentinel (the standard SAT solver output format).
        Positive integers map to ``1``, negatives to ``0``.

        INPUT:

            - ``line`` -- string; the assignment line (sentinel ``0`` included)

        OUTPUT:

            - dictionary mapping each variable index to ``0`` or ``1``
        """
        def __get_val(var):
            if int(var) < 0:
                return 0
            elif int(var) > 0:
                return 1
            else:
                raise AssertionError("Encountered 0 while parsing .sat")

        tokens = line.split(" ")[:-1]
        return {abs(int(var)): __get_val(var) for var in tokens}

    @abstractmethod
    def _process_solution_file(self, solution_file):
        """
        Extract the satisfiability and the variable assignment of the solution.

        INPUT:

            - ``solution_file``-- path to the file containing the solution

        OUTPUT:

            - ``satisfiability`` -- bool

            - ``assingment`` -- dictionary; the assignment of the variables in the solution. Empty if the problem is unsatisfiable
        """
        pass

class LOGIC_MINIMIZER_CVL(SOLVER_CVL, ABC):
    """
    Abstract base class for implementing an interface to a logic minizers.
    """
    def __init__(self):
        """Initizialize the minimizer interface."""
        super().__init__()

    def solve(self, input_file, time_limit=None):
        """
        Logic minimizers must only implement the ``invoke`` method.
        """
        raise NotImplementedError


class GUROBI_CVL(MILP_SOLVER_CVL):
    """
    Interface to the Gurobi MILP solver, see https://www.gurobi.com/.

    TODO: add examples for solve here
    """
    def __init__(self):
        """Initizialize the Gurobi interface."""
        super().__init__()
        self.name = "Gurobi"
        self.timeout_string = r"Time limit reached"
        self.bounds_regexp = r'Best objective (\S+), best bound (\S+), gap'
        self.can_solve_multiple = True

    def _build_command(self, input_file, solution_file, log_file, time_limit):
        """Build the Gurobi CLI command list."""
        command = ["gurobi_cl", f"ResultFile={solution_file}", f"LogFile={log_file}", str(input_file)]
        if time_limit is not None:
            command.insert(2, f"TimeLimit={time_limit}")
        return command

    def _process_solution_file(self, solution_file):
        """
        Extract the objective value and the variable assignment of the solution.

        INPUT:

            - ``solution_file``-- path to the file containing the solution

        OUTPUT:

            - ``objective_value`` -- float; the objective value of the solution

            - ``assingment`` -- dictionary; the assignment of the variables in the solution
        """
        assert isinstance(solution_file, Path)

        with solution_file.open("r") as f:
            file_content = f.read().split("\n")

        def __string_to_int_gurobi(str):
            """
            Remove rounding errors.

            Solution values can deviate up to 1e-5 from integer solutions, see
            https://support.gurobi.com/hc/en-us/articles/360012237872-Why-does-Gurobi-sometimes-return-non-integral-values-for-integer-variables
            """
            try:
                return int(str)
            except ValueError:
                value_float = float(str)
                value_int = int(round(value_float))
                if abs(value_float - value_int) < 1e-5:
                    return value_int
                raise ValueError(f"Deviation from integer to high: {str}")
        assert file_content != [''], "The model is UNSAT"

        objective_value = file_content[0][file_content[0].index('=')+2:]
        objective_value = _float_or_int(objective_value)
        assignment = {}
        for line in file_content[1:-1]:
            name = line[:line.index(" ")]
            value = __string_to_int_gurobi(line[line.index(" ")+1:])
            assignment[name] = value
        return  objective_value, _to_dict(assignment)

    def solve_multiple(self, input_file, number_of_solutions, time_limit=None):
        r"""
        Find the ``number_of_solutions`` best solutions to the model using Gurobi's solution pool.

        Gurobi pool parameters used:

        - ``PoolSolutions=n``: keep at most *n* solutions.
        - ``PoolSearchMode=2``: systematically enumerate pool solutions.
        - ``PoolGap=0``: only accept solutions matching the optimum.
        - ``SolFiles=<prefix>``: write pool solutions as ``<prefix>0.sol``, ``<prefix>1.sol``, ...

        .. SEEALSO::

            :meth:`civerly.solvers.SOLVER_CVL.solve_multiple`

        TODO: add examples for solve_multiple here
        """
        def _solutionpooljson_to_solfiles(json_file, solution_file):
            """Helper function to convert solutions from json to .sol files."""
            with json_file.open('r') as f:
                data = json.load(f)

            num_solutions = data['SolutionInfo']['SolCount']

            for sol_idx in range(num_solutions):
                obj_val = data['SolutionInfo']['PoolNObjVal'][sol_idx]

                sol_file = (solution_file.parent / f"{solution_file.stem}_{sol_idx}.sol")

                with sol_file.open('w') as f:
                    f.write(f"# Objective value = {obj_val}\n")

                    for var in data['Vars']:
                        var_name = var['VarName']
                        var_value = var['PoolNX'][sol_idx]
                        f.write(f"{var_name} {var_value}\n")
            return

        assert isinstance(input_file, Path)
        solution_file = input_file.parent / f"{input_file.stem}_{self.name}.sol"
        log_file = input_file.parent / f"{input_file.stem}_{self.name}.log"
        json_file = input_file.parent / f"{input_file.stem}_pool.json"

        command = [
            "gurobi_cl",
            "PoolSearchMode=2",
            f"LogFile={log_file}",
            f"PoolSolutions={number_of_solutions}",
            "JSONSolDetail=1",
            f"ResultFile={json_file}",
            str(input_file)
        ]

        if time_limit is not None:
            command.insert(2, f"TimeLimit={time_limit}")

        with suppress_output():
            process = subprocess.Popen(command)
            errno = process.wait()

        status = SOLVING_STATUS.SUCCESS
        if errno != 0:
            status = SOLVING_STATUS.ERROR

        if log_file.exists():
            with log_file.open('r') as file:
                if re.search(self.timeout_string, file.read(), re.MULTILINE):
                    status = SOLVING_STATUS.TIMEOUT

        # convert to seperate .sol files
        _solutionpooljson_to_solfiles(json_file, solution_file)

        # TODO: ensure correct functionality
        # use num_solutions from solutionpooljson_to_solfiles
        # then parse all the .sol files in the same way as in solve

        return results


class SCIP_CVL(MILP_SOLVER_CVL):
    """
    Interface to the SCIP solver, see https://scipopt.org/.

    TODO: add examples for solve
    """
    def __init__(self):
        """Initizialize the SCIP interface."""
        super().__init__()
        self.name = "SCIP"
        self.timeout_string = r"time limit reached"
        self.bounds_regexp = r'Primal Bound\s*:\s*(\S+).*\nDual Bound\s*:\s*(\S+).*'


    def invoke(self, input_file, solution_file, log_file, time_limit=None):
        """
        Invoke the SCIP solver via its CLI.

        SCIP needs a settings file alongside the command-line invocation; this
        method writes it before delegating to the shared MILP template and
        removes it afterwards.

        .. SEEALSO::

            :meth:`civerly.solvers.SOLVER_CVL.invoke`
        """
        try:
            with Path('scip_settings.set').open('w') as f:
                f.write('write/printzeros = TRUE')
                if time_limit is not None:
                    f.write(f"\nlimits/time = {time_limit}")
            return super().invoke(input_file, solution_file, log_file, time_limit)
        finally:
            Path("scip_settings.set").unlink(missing_ok=True)

    def _build_command(self, input_file, solution_file, log_file, time_limit):
        """Build the SCIP CLI command list."""
        return [
            "scip", "-c",
            (
                f"read {input_file} "
                "optimize write solution "
                f"{solution_file} "
                "quit"
            ),
            "-s", "scip_settings.set",
            "-l", str(log_file),
        ]

    def _process_solution_file(self, solution_file):
        """
        Parse a solution generated by SCIP.

        INPUT:

            - ``solution_file``-- name of the file containing a solution

        OUTPUT:

            - ``objective_value`` -- float; the objective value of the solution

            - ``assingment`` -- dictionary; the assignment of the variables in the solution
        """
        assert isinstance(solution_file, Path)

        with solution_file.open("r") as f:
            file_content = f.read().split("\n")

        if any(["infeasible" in line for line in file_content[:10]]):
            raise ValueError("There is no solution found!")
        assignment = {}
        objective_value = file_content[1].strip(" ")
        objective_value = objective_value[objective_value.index(":")+1:]
        objective_value = _float_or_int(objective_value)
        for line in file_content[2:-1]:
            line = line[:line.index("(")].replace(" ", "")
            value = int(round(float(line[line.index("]")+1:])))
            name = line[:line.index("]")+1]
            assignment[name] = value

        return  objective_value, _to_dict(assignment)


class GLPK_CVL(MILP_SOLVER_CVL):
    """
    Interface to the GLPK solver, see https://www.gnu.org/software/glpk/.

    TODO: add examples for solve
    """
    def __init__(self):
        """Initizialize the GLPK interface."""
        super().__init__()
        self.name = "GLPK"
        self.timeout_string = r"TIME LIMIT EXCEEDED"
        self.bounds_regexp = r'.*mip\s*=\s*(\S+)\s*>=\s*(\S+).*'

    def _build_command(self, input_file, solution_file, log_file, time_limit):
        """Build the GLPK CLI command list."""
        command = [
            "glpsol", str(input_file),
            "-o", str(solution_file),
            "--log", str(log_file),
        ]
        if time_limit is not None:
            command.insert(2, "--tmlim")
            command.insert(3, str(time_limit))
        return command

    def _process_solution_file(self, solution_file):
        """
        Parse a solution generated by GLPK.

        INPUT:

            - ``solution_file``-- name of the file containing a solution

        OUTPUT:

            - ``objective_value`` -- float; the objective value of the solution

            - ``assingment`` -- dictionary; the assignment of the variables in the solution
        """
        assert isinstance(solution_file, Path)

        with solution_file.open("r") as f:
            file_content = f.read().split("\n")

        if any(["INFEASIBLE" in line for line in file_content[-10:]]):
            raise ValueError("There is no solution found!")

        L, R = file_content[5].index("= ")+2, file_content[5].index("(")
        objective_value = _float_or_int(file_content[5][L:R])

        ind_start, ind_end = None, None
        bs, be = False, False

        # Cut off unnecessary lines
        for i_line, line in enumerate(file_content):
            if "No. Column name" in line:
                ind_start = i_line
                bs = True
            if "Integer feasibility conditions" in line:
                ind_end = i_line
                be = True
            if bs and be:
                break
        file_content = file_content[ind_start+2:ind_end]

        file_content = [
            line.replace(" ", "").replace("*", "")[:-2]
            for line in file_content
        ][:-1]
        file_content = [
            line[re.search(r'[A-Za-z]', line).start():]
            for line in file_content
        ]
        file_content = [line.replace(" ", "") for line in file_content]

        assignment = {}
        for line in file_content:
            i = line.index("]")
            name = line[:i+1]
            value = line[i+1:i+2]
            assignment[name] = value
        return objective_value, _to_dict(assignment)


class CRYPTOMINISAT_CVL(SAT_SOLVER_CVL):
    """
    Interface to the CryptoMinisat SAT solver, see https://github.com/msoos/cryptominisat.

    TODO: add examples for solve
    """
    def __init__(self):
        """Initizialize the CryptoMinisat interface."""
        super().__init__()
        self.name = "CryptoMiniSat"
        # 15 is CryptoMiniSat's exit code for "interrupted (time limit)".
        self.errno_map[15] = SOLVING_STATUS.TIMEOUT

    def _build_command(self, input_file, solution_file, log_file, time_limit):
        """Build the CryptoMinisat CLI command list."""
        command = [
            "cryptominisat5",
            "--presimp", "1",
            "--dumpresult", str(solution_file),
            str(input_file),
        ]
        if time_limit is not None:
            command.insert(1, "--maxtime")
            command.insert(2, str(time_limit))
        return command

    def _process_solution_file(self, solution_file):
        """
        Parse a solution generated by CryptoMinisat.

        INPUT:

            - ``solution_file``-- path to the file containing the solution

        OUTPUT:

            - ``satisfiability`` -- bool

            - ``assingment`` -- dictionary; the assignment of the variables in the solution. Empty if the problem is unsatisfiable
        """
        assert isinstance(solution_file, Path)

        with solution_file.open("r") as f:
            file_content = f.read().split("\n")

        if "UNSAT" in file_content[0]:
            return False, {}

        return True, self._parse_assignment_line(file_content[1])


class CADICAL_CVL(SAT_SOLVER_CVL):
    """
    Interface to the CaDiCaL SAT solver, see https://github.com/arminbiere/cadical.

    TODO: add examples for solve
    """
    def __init__(self):
        """Initizialize the CaDiCaL interface."""
        super().__init__()
        self.name = "CaDiCaL"

    def invoke(self, input_file, solution_file, log_file, time_limit=None):
        """
        Invoke the CaDiCaL solver, wrapping the shared template with a
        post-check on the solution file: CaDiCaL signals a timeout by writing
        ``c UNKNOWN`` rather than via an exit code.

        .. SEEALSO::

            :meth:`civerly.solvers.SOLVER_CVL.invoke`
        """
        status = super().invoke(input_file, solution_file, log_file, time_limit)
        if status == SOLVING_STATUS.SUCCESS:
            with solution_file.open('r') as file:
                if file.readline().strip("\n") == "c UNKNOWN":
                    status = SOLVING_STATUS.TIMEOUT
        return status

    def _build_command(self, input_file, solution_file, log_file, time_limit):
        """Build the CaDiCaL CLI command list."""
        command = [
            "cadical",
            str(input_file),
            "-P1",  # preprocess for 1 round
            "--sat",
            "-w", str(solution_file),
        ]
        if time_limit is not None:
            command.insert(2, "-t")
            command.insert(3, str(time_limit))
        return command

    def _process_solution_file(self, solution_file):
        """
        Parse a solution generated by CaDiCal.

        INPUT:

            - ``solution_file``-- name of the file containing a solution

        OUTPUT:

            - ``satisfiability`` -- bool

            - ``assingment`` -- dictionary; the assignment of the variables in the solution. Empty if the problem is unsatisfiable
        """
        assert isinstance(solution_file, Path)

        with solution_file.open("r") as f:
            file_content = f.read().split("\n")

        if "UNSATISFIABLE" in file_content[0]:
            return False, {}

        # strip leading "v "/"s " prefixes, then join all value lines into one
        file_content = [
            line[2:] if len(line) > 0 and line[0] in ["v", "s"] else line
            for line in file_content
        ]
        joined = ' '.join(file_content[1:-2])

        return True, self._parse_assignment_line(joined)


class ESPRESSO_CVL(LOGIC_MINIMIZER_CVL):
    """
    Interface to the Espresso minimizer, see e.g. https://github.com/hadipourh/espresso.

    TODO: add examples for invoke
    """
    def __init__(self):
        """Initizialize the Espresso interface."""
        super().__init__()
        self.name = "Espresso"

    def invoke(self, input_file, solution_file, log_file, time_limit=None):
        """
        Invoke the Espresso minimizer via its CLI.

        Espresso writes its output to stdout, so it cannot use the shared
        template (which would redirect to ``log_file`` at best). The
        ``time_limit`` parameter is ignored.

        .. SEEALSO::

            :meth:`civerly.solvers.SOLVER_CVL.invoke`
        """
        self._check_can_invoke(input_file, solution_file, log_file)
        command = self._build_command(input_file, solution_file, log_file, time_limit)
        with solution_file.open('a') as redirect:
            errno = subprocess.Popen(
                command, stdout=redirect, stderr=redirect
            ).wait()
        return self.errno_map.get(errno, SOLVING_STATUS.ERROR)

    def _build_command(self, input_file, solution_file, log_file, time_limit):
        """Build the Espresso CLI command list."""
        return ["espresso", "-epos", str(input_file)]


class NO_MILP_SOLVER_CVL(MILP_SOLVER_CVL):
    """
    Dummy MILP solver interface.

    If one of the supported solvers is used externally, this interface can be used to parse the results.

    TODO: add example
    """

    def __init__(self):
        """Initizialize the dummy interface."""
        super().__init__()
        self.name = "DummyMILPSolver"

    def invoke(self, input_file, solution_file, log_file, time_limit=None):
        """
        Raise an exception stating what files are expected. If they already exists, do nothing.

        INPUT:

            - ``input_file``-- path to the file containing the model

            - ``solution_file``-- path of the file in which the solver writes the solution

            - ``log_file``-- path to the solver's log file

            - ``time_limit``-- float (default ``None``); ignored

        OUTPUT:

            - Status, see :class:`civerly.solvers.SOLVING_STATUS`.
        """
        self._check_can_invoke(input_file, solution_file, log_file)

        # TODO:
        # if solution and log file are there: continue
        # else:
        # raise Exception stating the names of the files that are expected
        status = SOLVING_STATUS.SUCCESS

        # TODO: for MILP we should handle time out / interruptions also for external solvers.
        # to this end, we should outsource the check for a time out to a dedicated method which we can then overwrite in here.

        return status

    def _process_solution_file(self, solution_file):
        """
        Extract the objective value and the variable assignment of the solution.

        INPUT:

            - ``solution_file``-- path to the file containing the solution

        OUTPUT:

            - ``objective_value`` -- float; the objective value of the solution

            - ``assingment`` -- dictionary; the assignment of the variables in the solution
        """
        assert isinstance(solution_file, Path)

        with solution_file.open("r") as f:
            file_content = f.read().split("\n")

        # try to guess the solver
        if "# Objective value" in file_content[0]:
            return GUROBI_CVL()._process_solution_file(solution_file)
        elif "Problem:" in file_content[0] and "Rows:" in file_content[1]:
            return GLPK_CVL()._process_solution_file(solution_file)
        elif "solution status" in file_content[0]:
            return SCIP_CVL()._process_solution_file(solution_file)
        else:
            raise ValueError("Unknown solution format")

    def _get_objective_bounds(self, log_file):
        """
        Extract the bounds on the objective value from the log.

        This function is used when the MILP solver exceeds the given timeout.

        INPUT:

            - ``log_file``-- name of the log file

        OUTPUT:

            - tuple of floats; lower and upper bound for the optimal objective value
        """
        assert isinstance(log_file, Path)
        # TODO: determine solver and call corresponding method

    def _build_command(self, input_file, solution_file, log_file, time_limit):
        """Unused: the dummy overrides :meth:`invoke` and never runs a subprocess."""
        raise NotImplementedError(
            "The dummy MILP solver does not invoke a subprocess."
        )


class NO_SAT_SOLVER_CVL(SAT_SOLVER_CVL):
    """
    Dummy SAT solver interface.

    If one of the supported solvers is used externally, this interface can be used to parse the results.

    TODO: add example
    """

    def __init__(self):
        """Initizialize the dummy interface."""
        super().__init__()
        self.name = "DummySATSolver"

    def invoke(self, input_file, solution_file, log_file, time_limit=None):
        """
        Raise an exception stating what files are expected. If they already exists, do nothing.

        INPUT:

            - ``input_file``-- path to the file containing the model

            - ``solution_file``-- path of the file in which the solver writes the solution

            - ``log_file``-- path to the solver's log file

            - ``time_limit``-- float (default ``None``); ignored

        OUTPUT:

            - :attr:`civerly.solvers.SOLVING_STATUS.SUCCESS`
        """
        self._check_can_invoke(input_file, solution_file, log_file)

        # TODO:
        # if solution and log file are there: continue
        # else:
        # raise Exception stating the names of the files that are expected

        return SOLVING_STATUS.SUCCESS


    def _process_solution_file(self, solution_file):
        """
        Extract the satisfiability and the variable assignment of the solution.

        INPUT:

            - ``solution_file``-- path to the file containing the solution

        OUTPUT:

            - ``satisfiability`` -- bool

            - ``assingment`` -- dictionary; the assignment of the variables in the solution. Empty if the problem is unsatisfiable
        """
        assert isinstance(solution_file, Path)

        with solution_file.open("r") as f:
            file_content = f.read().split("\n")

        # try to guess the solver
        if "SATISFIABLE" in file_content[0]:  # also catches UNSATISFIABLE
            return CADICAL_CVL()._process_solution_file(solution_file)
        elif "SAT" in file_content[0]:  # also catches UNSAT
            return CRYPTOMINISAT_CVL()._process_solution_file(solution_file)
        else:
            raise ValueError("Unknown solution format")

    def _build_command(self, input_file, solution_file, log_file, time_limit):
        """Unused: the dummy overrides :meth:`invoke` and never runs a subprocess."""
        raise NotImplementedError(
            "The dummy SAT solver does not invoke a subprocess."
        )


class NO_LOGIC_MINIMIZER_CVL(LOGIC_MINIMIZER_CVL):
    """
    Dummy logic minimizer interface.

    If one of the supported minimizers is used externally, this interface can be used to parse the results.

    TODO: add example
    """

    def __init__(self):
        """Initizialize the dummy interface."""
        super().__init__()
        self.name = "DummyLogicMinimizer"

    def invoke(self, input_file, solution_file, log_file, time_limit=None):
        """
        Raise an exception stating what files are expected. If they already exists, do nothing.

        INPUT:

            - ``input_file``-- path to the file containing the model

            - ``solution_file``-- path of the file in which the solver writes the solution

            - ``log_file``-- path to the solver's log file

            - ``time_limit``-- float (default ``None``); ignored

        OUTPUT:

            - :attr:`civerly.solvers.SOLVING_STATUS.SUCCESS`
        """
        self._check_can_invoke(input_file, solution_file, log_file)

        # TODO:
        # if solution and log file are there: continue
        # else:
        # raise Exception stating the names of the files that are expected

        return SOLVING_STATUS.SUCCESS

    def _build_command(self, input_file, solution_file, log_file, time_limit):
        """Unused: the dummy overrides :meth:`invoke` and never runs a subprocess."""
        raise NotImplementedError(
            "The dummy logic minimizer does not invoke a subprocess."
        )
