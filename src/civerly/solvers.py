r"""
Utils for interacting with MILP and SAT solvers.
"""

import re
import json
import subprocess
import os
import warnings
import time
import shutil
from pathlib import Path
from enum import Enum

from sage.sat.solvers.dimacs import DIMACS
from civerly.util import _generate_constraints_sum_leq_int_LS24
from civerly.util import suppress_output, _float_or_int
from civerly.util import _to_dict

from abc import ABC, abstractmethod

class SOLVER_CVL(ABC):
    """
    Abstract base class for implementing an interface to a solver.
    """
    def __init__(self):
        """
        Initialize the solver interface.

        This shall set ``self.name``.
        """
        self.name = "GenericSolver"
        self.can_solve_multiple = False

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


    @abstractmethod
    def invoke(self, input_file, solution_file, log_file=None, time_limit=None):
        """
        Invoke the solver's CLI to solve the model in the given file.

        INPUT:

            - ``input_file``-- path to the file containing the model

            - ``solution_file``-- path of the file in which the solver writes the solution

            - ``log_file``-- path to the solver's log file. If ``None``, a default based on ``solution_file`` and ``self.name`` is used

            - ``time_limit``-- float (default ``None``); time limit in seconds

        OUTPUT:

            - Status, see :class:`civerly.solvers.SOLVING_STATUS`. Further, upon
              successful execution a solution is stored in ``solution_file``.
        """
        assert isinstance(input_file, Path)
        assert isinstance(solution_file, Path)

        # default log file
        if log_file is None:
            parent_dir = solution_file.parent
            name = f"{solution_file.stem}_{self.name}"
            suffix = ".log"
            log_file = parent_dir / (name + suffix)
        else:
            assert isinstance(log_file, Path)

        # you can disable a solver by setting an environment variable
        # with this we simulate that a solver is not installed albeit it is
        # i.e. this is used for testing only
        ENV_DISABLE_PREFIX = "CIVERLY_DISABLE_"
        if ENV_DISABLE_PREFIX+self.name in os.environ:
            raise ValueError(
                f"{self.name} was disabled by setting environment variable "
                f"{ENV_DISABLE_PREFIX+self.name}"
            )


class MILP_SOLVER_CVL(SOLVER_CVL, ABC):
    """Abstract base class for implementing an interface to a MILP solver."""

    def __init__(self):
        """Initizialize the MILP solver interface."""
        super().__init__()

    @abstractmethod
    def solve(self, input_file, time_limit=None):
        """
        Solve the model in the given file.

        INPUT:

            - ``input_file`` -- path to the file containing the model

            - ``time_limit`` -- float or ``none`` (default ``none``); time limit in seconds

        OUTPUT:

            - ``result`` -- a dictionary with at least the following entries:

                - ``status`` -- see :class:`civerly.solvers.solving_status`
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
        status = self.invoke(input_file, solution_file, log_file=log_file, time_limit=time_limit)
        solve_time = start_time - time.perf_counter()

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

    @abstractmethod
    def _get_objective_bounds(self, log_file):
        """
        Extract the bounds on the objective value from the log of an MILP solver.

        This function is used when the MILP solver exceeds the given timeout.

        INPUT:

            - ``log_file``-- name of the log file

        OUTPUT:

            - tuple of floats; lower and upper bound for the optimal objective value
        """
        pass

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


class SAT_SOLVER_CVL(SOLVER_CVL):
    """Abstract base class for implementing an interface to a SAT solver."""

    def __init__(self):
        """Initizialize the SAT solver interface."""
        super().__init__()

    def solve(self, input_file, time_limit=None):
        """
        Solve the model in the given file.

        Input:

            - ``input_file`` -- path to the file containing the model

            - ``time_limit`` -- float or ``none`` (default ``none``); time limit in seconds

        Output:

            - ``result`` -- a dictionary with at least the following entries:

                - ``status`` -- see :class:`civerly.solvers.solving_status`
                - ``satisfiability`` -- bool or ``None``
                - ``assingment`` -- dictionary; the assignment of the variables in the solution
                - ``solve_time`` -- float; time (in seconds) it took to find this solution
        """
        start_time = time.perf_counter()
        solution_file = input_file.parent / f"{input_file.stem}_{self.name}.sat"
        status = self.invoke(input_file, solution_file, log_file=None, time_limit=time_limit)
        solve_time = start_time - time.perf_counter()

        if status == SOLVING_STATUS.SUCCESS:
            satisfiability, assignment = self._process_solution_file(solution_file)
        else:
            satisfiability = None
            assignment = {}

        result = {"status": status, "satisfiability": satisfiability, "assingment": assignment, "solve_time": solve_time}
        return result

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
        self.can_solve_multiple = True

    def invoke(self, input_file, solution_file, log_file=None, time_limit=None):
        """
        Invoke the Gurobi solver via its CLI.

        .. SEEALSO::

            :meth:`civerly.solvers.SOLVER_CVL.invoke`
        """
        super().invoke(input_file, solution_file, log_file, time_limit)
        command = ["gurobi_cl", f"ResultFile={solution_file}", f"LogFile={log_file}", str(input_file)]
        if time_limit is not None:
            command.insert(2, f"TimeLimit={time_limit}")

        with suppress_output():
            process = subprocess.Popen(command)
            errno = process.wait()

        status = SOLVING_STATUS.SUCCESS
        if errno != 0:
            status = SOLVING_STATUS.ERROR

        if time_limit is not None:
            # check if the solver reported a time out by checking the log file
            # for an according string
            with log_file.open("r") as file:
                content = file.read()
            if re.search(self.timeout_string, content, re.MULTILINE):
                status = SOLVING_STATUS.TIMEOUT

        return status

    def _get_objective_bounds(self, log_file):
        """
        Extract the bounds on the objective value from the Gurobi log.

        This function is used when the MILP solver exceeds the given timeout.

        INPUT:

            - ``log_file``-- name of the log file

        OUTPUT:

            - tuple of floats; lower and upper bound for the optimal objective value
        """
        assert isinstance(log_file, Path)

        regexp = r'Best objective (\S+), best bound (\S+), gap'

        with log_file.open('r') as file:
            content = file.read()

        hit = re.search(regexp, content, re.MULTILINE)
        if hit:
            upper_bound = _float_or_int(hit.group(1))
            lower_bound = _float_or_int(hit.group(2))
            return lower_bound, upper_bound

        warnings.warn(f"No objective bounds found in {log_file}")
        return None, None

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
        - ``SolFiles=<prefix>``: write pool solutions as ``<prefix>0.sol``, ``<prefix>1.sol``, …

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
        solution_file = input_file.parent / f"{input_file.stem}_{self.name}.sat"
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


    def invoke(self, input_file, solution_file, log_file=None, time_limit=None):
        """
        Invoke the SCIP solver via its CLI.

        .. SEEALSO::

            :meth:`civerly.solvers.SOLVER_CVL.invoke`
        """
        super().invoke(input_file, solution_file, log_file, time_limit)
        if time_limit is not None:
            with Path('scip_settings.set').open('w') as f:
                f.write(f"write/printzeros = TRUE\nlimits/time = {time_limit}")
        else:
            with Path('scip_settings.set').open('w') as f:
                f.write('write/printzeros = TRUE')
        command = [
            "scip", "-c",
            (
                f"read {input_file} "
                "optimize write solution "
                f"{solution_file} "
                "quit"
            ),
            "-s", "scip_settings.set",
        ]
        # only add -l flag when log_file_name is set
        if log_file is not None:
            command += ["-l", str(log_file)]

        with suppress_output():
            process = subprocess.Popen(command)
            errno = process.wait()

        status = SOLVING_STATUS.SUCCESS
        if errno != 0:
            status = SOLVING_STATUS.ERROR

        if time_limit is not None:
            # check if the solver reported a time out by checking the log file
            # for an according string
            with log_file.open('r') as file:
                content = file.read()
            if re.search(self.timeout_string, content, re.MULTILINE):
                status = SOLVING_STATUS.TIMEOUT

        # clean up
        Path("scip_settings.set").unlink(missing_ok=True)

        return status

    def _get_objective_bounds(self, log_file):
        """
        Extract the bounds on the objective value from the SCIP log.

        This function is used when the MILP solver exceeds the given timeout.

        INPUT:

            - ``log_file``-- name of the log file

        OUTPUT:

            - tuple of floats; lower and upper bound for the optimal objective value
        """
        assert isinstance(log_file, Path)
        regexp = r'Primal Bound\s*:\s*(\S+).*\nDual Bound\s*:\s*(\S+).*'

        with log_file.open('r') as file:
            content = file.read()

        hit = re.search(regexp, content, re.MULTILINE)
        if hit:
            upper_bound = _float_or_int(hit.group(1))
            lower_bound = _float_or_int(hit.group(2))
            return lower_bound, upper_bound

        warnings.warn(f"No objective bounds found in {log_file}")
        return None, None

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

        with open(solution_file, "r") as f:
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
    def __init__(self):
        super().__init__()
        self.name = "GLPK"
        self.timeout_string = r"TIME LIMIT EXCEEDED"

    def invoke(self, input_file, solution_file,
              log_file=None, time_limit=None):
        r"""Invoke GLPK solver via shell."""
        super().invoke(
            input_file, solution_file, log_file, time_limit
        )
        command = [
            "glpsol", str(input_file),
            "-o", str(solution_file)
        ]
        # only add --log flag when log_file is set
        if log_file is not None:
            command += ["--log", str(log_file)]

        if time_limit is not None:
            command.insert(2, "--tmlim")
            command.insert(3, str(time_limit))

        with suppress_output():
            process = subprocess.Popen(command)
            errno = process.wait()

        if errno != 0:
            self.status = SOLVING_STATUS.ERROR

        if time_limit is not None:
            # check if the solver reported a time out by checking the log file
            # for an according string
            with open(log_file, 'r') as file:
                content = file.read()
            if re.search(self.timeout_string, content, re.MULTILINE):
                self.status = SOLVING_STATUS.TIMEOUT

        return

    def _get_objective_bounds(self, log_file):
        """
        Extract the bounds on the objective value from the log of an MILP solver.

        This function shall be used when the MILP solver exceeds the given timeout.

        INPUT:

            - ``log_file``-- name of the log file

        """
        assert isinstance(log_file, Path)
        regexp = r'.*mip\s*=\s*(\S+)\s*>=\s*(\S+).*'

        with open(log_file, 'r') as file:
            content = file.read()

        hit = re.search(regexp, content, re.MULTILINE)
        if hit:
            upper_bound = _float_or_int(hit.group(1))
            lower_bound = _float_or_int(hit.group(2))
            return lower_bound, upper_bound

        warnings.warn(f"No objective bounds found in {log_file}")
        return None, None

    def _process_solution_file(self, solution_file):
        """
        Parse a solution generated by GLPK.

        INPUT:

            - ``solution_file``-- name of the file containing a solution

        OUTPUT: The processed ``results`` and ``objective_value``.
        """
        assert isinstance(solution_file, Path)

        with open(solution_file, "r") as f:
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

        results = {}
        for line in file_content:
            i = line.index("]")
            name = line[:i+1]
            value = line[i+1:i+2]
            results[name] = value
        return _to_dict(results), objective_value


class CRYPTOMINISAT_CVL(SAT_SOLVER_CVL):
    def __init__(self):
        super().__init__()
        self.name = "CryptoMiniSat"

    def invoke(self, input_file, solution_file,
              log_file=None, time_limit=None):
        r"""Invoke CryptoMiniSat solver via shell."""
        super().invoke(
            input_file, solution_file, log_file, time_limit
        )
        command = [
            "cryptominisat5",
            "--presimp", "1",
            "--dumpresult", solution_file,
            input_file
        ]
        if time_limit is not None:
            command.insert(1, "--maxtime")
            command.insert(2, str(time_limit))

        if log_file is not None:
            self.redirect_stdout = open(log_file, 'a')

        with suppress_output():
            process = subprocess.Popen(
                command, stdout=self.redirect_stdout,
                stderr=self.redirect_stdout
            )
            errno = process.wait()

        if log_file is not None:
            self.redirect_stdout.close()

        if errno != 0:
            # 10: SAT, 20: UNSAT
            if errno in [10, 20]:
                pass
            elif errno == 15:
                self.status = SOLVING_STATUS.TIMEOUT
            else:
                self.status = SOLVING_STATUS.ERROR

        return

    def _process_solution_file(self, solution_file):
        """
        Parse '.sat' files and recover the variable assignments as well as the
        objective value.

        INPUT:

            - ``solution_file``-- name of the file containing a solution

        OUTPUT: The processed ``results`` and ``objective_value``.

        .. NOTE::

            CiVerLy augments the standard file format convention for SAT output
            files. Typically the first line holds the string 'SAT' or 'UNSAT',
            while the variable assignments are given in the second line, in form of
            the **sign** of the corresponding integer. Additionally, CiVerLy
            writes the objective value into the second line, as an integer, which
            is non-standard.
        """
        assert isinstance(solution_file, Path)

        with open(solution_file, "r") as f:
            file_content = f.read().split("\n")

        if "UNSAT" in file_content[0]:
            raise AssertionError("The model is UNSAT")

        def __get_val(var):
            if int(var) < 0:
                return 0
            elif int(var) > 0:
                return 1
            else:
                raise AssertionError("Encountered 0 while parsing .sat")

        results = file_content[1].split(" ")[:-1]
        results = {abs(int(var)): __get_val(var) for var in results}
        objective_value = _float_or_int(file_content[2])

        return results, objective_value


class CADICAL_CVL(SAT_SOLVER_CVL):
    def __init__(self):
        super().__init__()
        self.name = "CaDiCal"

    def invoke(self, input_file, solution_file,
              log_file=None, time_limit=None):
        r"""Invoke CaDiCal solver via shell."""
        super().invoke(
            input_file, solution_file, log_file, time_limit
        )
        command = [
            "cadical",
            str(input_file),
            "-P1", # preprocess for 1 round
            "--sat",
            "-w", str(solution_file)
        ]
        if time_limit is not None:
            command.insert(2, "-t")
            command.insert(3, str(time_limit))

        if log_file is not None:
            self.redirect_stdout = open(log_file, 'a')

        with suppress_output():
            process = subprocess.Popen(
                command, stdout=self.redirect_stdout,
                stderr=self.redirect_stdout
            )
            errno = process.wait()

        if log_file is not None:
            self.redirect_stdout.close()

        if errno != 0:
            # 10: SAT, 20: UNSAT
            if errno in [10, 20]:
                pass
            else:
                self.status = SOLVING_STATUS.ERROR

        # if there was no error but there is no solution, we conclude that
        # there was a time out
        if self.status == SOLVING_STATUS.SUCCESS:
            with open(solution_file, 'r') as file:
                line = file.readline().strip("\n")
            if line == "c UNKNOWN":
                self.status = SOLVING_STATUS.TIMEOUT

        return

    def _process_solution_file(self, solution_file):
        """
        Parse a solution generated by CaDiCal.

        INPUT:

            - ``solution_file``-- name of the file containing a solution

        OUTPUT: The processed ``results`` and ``objective_value``.
        """
        assert isinstance(solution_file, Path)

        with open(solution_file, "r") as f:
            file_content = f.read().split("\n")

        if "UNSATISFIABLE" in file_content[0]:
            raise AssertionError("The model is UNSAT")

        file_content = [
            line[2:] if len(line) > 0 and line[0] in ["v", "s"] else line
            for line in file_content
        ]
        joined = ' '.join(file_content[1:-2])
        file_content = [file_content[0], joined, file_content[-2]]

        def __get_val(var):
            if int(var) < 0:
                return 0
            elif int(var) > 0:
                return 1
            else:
                raise AssertionError("Encountered 0 while parsing .sat")

        results = file_content[1].split(" ")[:-1]
        results = {abs(int(var)): __get_val(var) for var in results}
        objective_value = _float_or_int(file_content[2])

        return results, objective_value


class ESPRESSO_CVL(LOGIC_MINIMIZER_CVL):
    def __init__(self):
        super().__init__()
        self.name = "Espresso"

    def invoke(self, input_file, solution_file,
               log_file=None, time_limit=None):
        r"""Invoke Espresso logic minimizer via shell."""
        super().invoke(
            input_file, solution_file,
            log_file=None, time_limit=None
        )
        command = [
            "espresso",
            "-epos",
            str(input_file)
        ]

        self.redirect_stdout = open(solution_file, 'a')

        # with suppress_output():
        if True:
            process = subprocess.Popen(
                command, stdout=self.redirect_stdout,
                stderr=self.redirect_stdout
            )
            errno = process.wait()

        self.redirect_stdout.close()

        # failure: errno 1
        if errno != 0:
            self.status = SOLVING_STATUS.ERROR

        return


class NO_MILP_SOLVER_CVL(MILP_SOLVER_CVL):
    def solve(self, input_file, solution_file, time_limit=None):
        raise NoSolverWarning()

    def solve_multiple(self, model_options, cipher=None, time_limit=None):
        raise NoSolverWarning()

    def _process_solution_file(self, solution_file):
        """
        Internal helper method to process the solution file.

        INPUT:

            - ``solution_file``-- name of the file containing a solution
            - ``solver`` -- the used solver, see
            :class:`civerly.model_options.SOLVER`

        OUTPUT: The processed ``results`` and ``objective_value``.
        """
        assert isinstance(solution_file, Path)

        with open(solution_file, "r") as f:
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


class NO_SAT_SOLVER_CVL(SAT_SOLVER_CVL):
    def solve(self, input_file, solution_file, model_options,
              time_limit=None):
        """
        If no solver is selected, generate all cnf's in solve_range
        and let user solve them externally.
        """
        assert isinstance(input_file, Path)
        assert isinstance(solution_file, Path)

        # shorten variable name
        pr = model_options.sat_precision

        def __get_sum_arr():
            r"""
            Implicit helper function to read and extract the sum_arr from the
            corresponding json file.
            """
            sum_arr_file = input_file.parent / f"{input_file.stem}sum.json"
            with open(sum_arr_file, 'r') as f:
                file_content = json.load(f)

                # Scale all weights by 10**sat_precision
                # (and normalize again later)
                sum_arr = [
                    (weight, var)
                    for weight, var in file_content
                ]
            return sum_arr

        # scale W_MIN, W_MAX too
        W_MIN = int(model_options.solve_range[0] * 10**pr)
        W_MAX = int(model_options.solve_range[1] * 10**pr)

        for w in range(W_MIN, W_MAX):
            sat = DIMACS()
            sat.read(str(input_file))

            sat_constraining_prob = _generate_constraints_sum_leq_int_LS24(
                sat,
                __get_sum_arr(),
                w
            )

            # temporary files with encoded weight w
            name = f"{input_file.stem}_obj{w/10**pr}"
            tmp_cnf_file_name = input_file.parent / f"{name}.cnf"
            sat_constraining_prob.write(tmp_cnf_file_name)
        return

    def _process_solution_file(self, solution_file):
        """
        Internal helper method to process the solution file.

        INPUT:

            - ``solution_file``-- name of the file containing a solution
            - ``solver`` -- the used solver, see
            :class:`civerly.model_options.SOLVER`

        OUTPUT: The processed ``results`` and ``objective_value``.
        """
        assert isinstance(solution_file, Path)

        with open(solution_file, "r") as f:
            file_content = f.read().split("\n")

        # try to guess the solver
        if "SATISFIABLE" in file_content[0]:  # also catches UNSATISFIABLE
            return CADICAL_CVL()._process_solution_file(solution_file)
        elif "SAT" in file_content[0]:  # also catches UNSAT
            return CRYPTOMINISAT_CVL()._process_solution_file(solution_file)
        else:
            raise ValueError("Unknown solution format")

    def solve_multiple(self, model_options, cipher=None, time_limit=None):
        raise NoSolverWarning()


class NO_LOGIC_MINIMIZER_CVL(LOGIC_MINIMIZER_CVL):
    def __init__(self):
        super().__init__()

    def solve(self, input_file, solution_file):
        raise NoSolverWarning()


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


class SolverException(Exception):
    def __init__(self, e):
        if e == SOLVING_STATUS.TIMEOUT:
            super().__init__("Solver / Minimizer timed out.")
        elif e == SOLVING_STATUS.ERROR:
            super().__init__("Solver / Minimizer raised an external error.")
