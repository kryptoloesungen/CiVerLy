r"""
Utils for interacting with MILP and SAT solvers.
"""

import re
import json
import hashlib
import subprocess
import os
import warnings
import time
from pathlib import Path
from enum import Enum

from sage.sat.solvers.dimacs import DIMACS

from civerly.util import suppress_output

from abc import ABC, abstractmethod


def _float_or_int(value):
    """
    Cast ``value`` to float or int if possible.

    EXAMPLES::

        sage: from civerly.solvers import _float_or_int
        sage: _float_or_int(42.0)
        42
        sage: _float_or_int(42.5)
        42.5
        sage: _float_or_int("42.000")
        42
        sage: _float_or_int("42.001")
        42.001
        sage: _float_or_int("3.415037499300e+00")
        3.4150374993
    """
    value = float(value)
    if value.is_integer() or abs(value - int(round(value))) < 1e-8:
        value = int(round(value))
    else:
        value = round(value, 10)
    return value


def _to_dict(flat_results):
    r"""
    Convert a flat results dict to a nested one, grouping by variable
    name and using the bracket index as an integer key.

    EXAMPLES::

        sage: from civerly.solvers import _to_dict
        sage: _to_dict({'Z[0]': 1, 'Z[1]': 2})
        {'Z': {0: 1, 1: 2}}
    """
    nested = {}
    for variable, value in flat_results.items():
        var_name, rest = variable.split("[", 1)
        var_index = int(rest.rstrip("]"))
        nested.setdefault(var_name, {})[var_index] = value
    return nested

def _content_hash(path, length=8):
    r"""
    Return the first ``length`` hex digits of the SHA-256 of the file at
    ``path``. Used to make solution-file names depend on model content so
    that a stale solution file from a previous model is not picked up by
    the cache.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()[:length]


class SOLVING_STATUS(Enum):
    """Indicate if solving was successful or what went wrong."""

    SUCCESS = 1
    TIMEOUT = 2
    ERROR = 3


class ExternalSolveRequired(Exception):
    """
    Raised when an external solver is invoked but the solution file is not
    yet present. Provide a solution at the path shown in the message and
    re-run.
    """


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
        # exit-code -> SOLVING_STATUS. Unknown codes default to ERROR.
        self.errno_map = {0: SOLVING_STATUS.SUCCESS}
        # If True, ``invoke`` redirects subprocess stdout/stderr into ``log_file``.
        # Solvers that write their own log via CLI flags leave this False.
        self.store_stdout = False

    def _check_can_invoke(self, input_file, solution_file, log_file):
        """
        Verify the inputs and check if a solver has been disabled.

        You can disable a solver by setting the environment variable
        ``CIVERLY_DISABLE_<NAME>``. We use this to simulate that a solver
        is not installed albeit it is. This is used for testing only.

        This is called by :meth:`invoke` and is also exposed for subclasses
        that override :meth:`invoke` entirely and still need the standard
        precondition checks.
        """
        assert isinstance(input_file, Path)
        assert isinstance(solution_file, Path)
        assert isinstance(log_file, Path)

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
        # Subclasses set this to a regex matched against ``log_file`` to detect
        # a reported timeout. Leave ``None`` to skip the log-based check.
        self.timeout_string = None

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
                - ``assignment`` -- dictionary; the assignment of the variables in the solution
                - ``solve_time`` -- float; time (in seconds) it took to find this solution

        .. Warning::

            If ``time_limit`` is reached, the solution might be non-optimal.
        """
        h = _content_hash(input_file)
        solution_file = input_file.parent / f"{input_file.stem}.{h}.sol"
        log_file = input_file.parent / f"{input_file.stem}_{self.name}.log"

        if solution_file.exists():
            print(
                f"Using existing file {solution_file}, "
                "make sure it is up to date!"
            )
            objective_value, assignment = self._process_solution_file(solution_file)
            return {
                "status": SOLVING_STATUS.SUCCESS,
                "objective_value": objective_value,
                "objective_bounds": (objective_value, objective_value),
                "assignment": assignment,
                "solve_time": 0.0,
            }

        start_time = time.perf_counter()
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

        result = {"status": status, "objective_value": objective_value, "objective_bounds": objective_bounds, "assignment": assignment, "solve_time": solve_time}
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

        Returns ``status`` unchanged if ``time_limit`` is ``None`` or if the
        subclass did not configure ``self.timeout_string``. Otherwise
        ``log_file`` is searched for ``self.timeout_string`` and
        ``SOLVING_STATUS.TIMEOUT`` is returned on a hit.

        INPUT:

            - ``log_file`` -- path to the log file
            - ``time_limit`` -- float or ``None``; the time limit passed to the solver
            - ``status`` -- the current :class:`SOLVING_STATUS`

        OUTPUT:

            - the (possibly updated) :class:`SOLVING_STATUS`
        """
        if time_limit is None or self.timeout_string is None:
            return status
        with log_file.open('r') as file:
            content = file.read()
        if re.search(self.timeout_string, content, re.MULTILINE):
            return SOLVING_STATUS.TIMEOUT
        return status

    def solve_multiple(self, input_file, milp, number_of_solutions,
                       trail_vars=None, time_limit=None):
        r"""
        Find up to ``number_of_solutions`` distinct solutions by repeated
        solving with blocking constraints. Each iteration adds a constraint
        to ``milp`` excluding the previous assignment and flushes ``milp``
        back to ``input_file`` before the next solve.

        ``milp`` is required because Sage's ``MixedIntegerLinearProgram``
        cannot reconstruct itself from an MPS file -- the in-memory model
        must be threaded through from where it was built.

        Stops early if a solve fails or no feasible solution is found.

        INPUT:

            - ``input_file`` -- path to the MPS file; rewritten between iterations
            - ``milp`` -- in-memory :class:`MixedIntegerLinearProgram` whose
              state matches ``input_file``
            - ``number_of_solutions`` -- maximum number of solutions to find
            - ``trail_vars`` -- optional iterable of MPS variable names that
              define "the trail". When provided, exclusion constraints only
              involve these variables; assignments that differ only on
              helper variables are treated as the same solution. When
              ``None``, every variable in the assignment is used.
            - ``time_limit`` -- float or ``None``; per-iteration time limit

        OUTPUT:

            - list of result dicts in the same shape as :meth:`solve` returns,
              ordered best (lowest objective) first
        """
        results = []
        for i in range(number_of_solutions):
            r = self.solve(input_file, time_limit=time_limit)
            results.append(r)
            done = (r["status"] != SOLVING_STATUS.SUCCESS
                    or r["objective_value"] is None)
            if done or i == number_of_solutions - 1:
                break
            self._exclude_assignment(milp, r["assignment"], trail_vars=trail_vars)
            with suppress_output():
                milp.write_mps(str(input_file))
        return results

    def _exclude_assignment(self, milp, assignment, trail_vars=None):
        r"""
        Add a constraint to ``milp`` that excludes ``assignment``. The caller
        is responsible for flushing ``milp`` to disk before the next solve.

        The constraint forces at least one variable to differ from its
        assigned value:

        .. math::
            \sum_{x_i = 0} x_i + \sum_{x_i = 1} (1 - x_i) \geq 1

        If ``trail_vars`` is provided, only variables whose MPS name is in
        ``trail_vars`` participate in the constraint; helpers are ignored.
        Otherwise every variable in ``assignment`` is constrained.
        """
        # Flatten the nested ``{name: {idx: val}}`` shape (from
        # ``_process_solution_file``) back to the flat MPS variable names.
        flat = {}
        for name, sub in assignment.items():
            if isinstance(sub, dict):
                for idx, val in sub.items():
                    flat[f"{name}[{idx}]"] = val
            else:
                flat[name] = sub

        if trail_vars is not None:
            trail_vars = set(trail_vars)
            flat = {name: val for name, val in flat.items() if name in trail_vars}

        b = milp.get_backend()
        coefs = []
        n_ones = 0
        for i in range(b.ncols()):
            name = b.col_name(i)
            if name not in flat:
                continue
            val = flat[name]
            n_ones += val
            coefs.append((i, 1.0 if val == 0 else -1.0))
        # sum_{x_i=0} x_i - sum_{x_i=1} x_i >= 1 - n_ones
        b.add_linear_constraint(coefs, 1 - n_ones, None)

    @abstractmethod
    def _process_solution_file(self, solution_file):
        """
        Extract the objective value and the variable assignment of the solution.

        INPUT:

            - ``solution_file``-- path to the file containing the solution

        OUTPUT:

            - ``objective_value`` -- float; the objective value of the solution

            - ``assignment`` -- dictionary; the assignment of the variables in the solution
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

    def decide(self, input_file, time_limit=None):
        """
        Decide whether the CNF in ``input_file`` is satisfiable, and if so,
        return one satisfying assignment.

        This is the SAT solver's native one-shot operation. Use :meth:`solve`
        instead to find the minimum-weight satisfying assignment via binary
        search.

        INPUT:

            - ``input_file`` -- path to the file containing the CNF

            - ``time_limit`` -- float or ``None`` (default ``None``); time limit in seconds

        OUTPUT:

            - ``result`` -- a dictionary with the following entries:

                - ``status`` -- see :class:`civerly.solvers.SOLVING_STATUS`
                - ``satisfiability`` -- bool or ``None``
                - ``assignment`` -- dictionary; the assignment of the variables in the solution
                - ``solve_time`` -- float; time (in seconds) it took to find this solution
        """
        h = _content_hash(input_file)
        solution_file = input_file.parent / f"{input_file.stem}.{h}.sat"
        log_file = input_file.parent / f"{input_file.stem}_{self.name}.log"

        if solution_file.exists():
            print(
                f"Using existing file {solution_file}, "
                "make sure it is up to date!"
            )
            satisfiability, assignment = self._process_solution_file(solution_file)
            return {
                "status": SOLVING_STATUS.SUCCESS,
                "satisfiability": satisfiability,
                "assignment": assignment,
                "solve_time": 0.0,
            }

        start_time = time.perf_counter()
        status = self.invoke(input_file, solution_file, log_file, time_limit=time_limit)
        solve_time = time.perf_counter() - start_time

        if status == SOLVING_STATUS.SUCCESS:
            satisfiability, assignment = self._process_solution_file(solution_file)
        else:
            satisfiability = None
            assignment = {}

        result = {"status": status, "satisfiability": satisfiability, "assignment": assignment, "solve_time": solve_time}
        return result

    def solve(self, input_file, sum_arr_file, solve_range, precision=0, time_limit=None):
        r"""
        Find the lowest weight ``w`` in ``solve_range`` for which the CNF in
        ``input_file``, augmented with ``sum(weight_i * var_i) <= w`` using
        the sum array stored in ``sum_arr_file``, remains satisfiable.

        Internally, this performs a binary search over the range, calling
        :meth:`decide` on each constrained CNF.

        INPUT:

            - ``input_file`` -- path to the base CNF

            - ``sum_arr_file`` -- path to the JSON file containing the sum
              array, i.e. a list of ``(weight, var)`` pairs

            - ``solve_range`` -- ``(lower, upper)`` pair of floats bounding
              the search

            - ``precision`` -- integer (default ``0``); the weights are
              scaled by ``10**precision`` before searching, so this is the
              number of decimal digits considered

            - ``time_limit`` -- float or ``None`` (default ``None``); total
              time limit in seconds across all iterations

        OUTPUT:

            - ``result`` -- a dictionary with the same shape as
              :meth:`civerly.solvers.MILP_SOLVER_CVL.solve`:

                - ``status`` -- see :class:`civerly.solvers.SOLVING_STATUS`
                - ``objective_value`` -- the minimum weight (the objective),
                  or ``None`` if no satisfying assignment was found in the
                  range or on early termination
                - ``objective_bounds`` -- ``(lower, upper)`` proven bounds on
                  the optimum. ``(opt, opt)`` on a tight solve, the still-open
                  interval on timeout, ``(None, None)`` on error or when no
                  feasible solution exists.
                - ``assignment`` -- dictionary; the assignment of the
                  variables at the minimum weight, empty if unsatisfiable
                - ``solve_time`` -- float; total time spent
                - ``trace`` -- an additional dicitionary that holds the result
                  of each call to :meth:``decide``. The keys of ``trace``
                  correspond to the tested weights.
        """
        assert isinstance(input_file, Path)
        assert isinstance(sum_arr_file, Path)

        start_time = time.perf_counter()
        deadline = start_time + time_limit if time_limit is not None else None
        trace = {}

        with sum_arr_file.open('r') as f:
            sum_arr = json.load(f)

        scale = 10 ** precision
        W_MIN = int(solve_range[0] * scale)
        W_MAX = int(solve_range[1] * scale)
        if W_MIN > W_MAX:
            raise ValueError(f"Invalid solve_range: {solve_range}")

        def _format_weight(w):
            return w / scale if precision else int(w)

        def _early_return(status):
            if status == SOLVING_STATUS.TIMEOUT:
                bounds = (_format_weight(W_MIN), _format_weight(W_MAX))
                if last_sat is not None:
                    return {
                        "status": status,
                        "objective_value": _format_weight(W_MAX),
                        "objective_bounds": bounds,
                        "assignment": last_sat["assignment"],
                        "solve_time": time.perf_counter() - start_time,
                    }
            else:
                bounds = (None, None)
            return {
                "status": status,
                "objective_value": None,
                "objective_bounds": bounds,
                "assignment": {},
                "solve_time": time.perf_counter() - start_time,
                "trace": trace,
            }

        def _decide_at(w):
            sat = DIMACS()
            sat.read(str(input_file))
            constrained = self._generate_constraints_sum_leq_int_LS24(sat, sum_arr, int(w))
            tmp_cnf = input_file.parent / f"{input_file.stem}_obj{w}.cnf"
            constrained.write(tmp_cnf)
            if deadline is not None:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    return SOLVING_STATUS.TIMEOUT
            else:
                remaining = None
            trace[w] = self.decide(tmp_cnf, time_limit=remaining)
            return trace[w]

        last_sat = None
        while W_MIN < W_MAX:
            w = (W_MIN + W_MAX) // 2
            r = _decide_at(w)

            if r["status"] == SOLVING_STATUS.TIMEOUT:
                return _early_return(SOLVING_STATUS.TIMEOUT)
            elif r["status"] != SOLVING_STATUS.SUCCESS:
                return _early_return(r["status"])

            if r["satisfiability"]:
                last_sat = r
                W_MAX = w
            else:
                W_MIN = w + 1

        # Loop exited with W_MIN == W_MAX. If we never proved this value SAT,
        # test it once more to distinguish "optimum found" from "all UNSAT".
        if last_sat is None:
            r = _decide_at(W_MIN)

            if r["status"] == SOLVING_STATUS.TIMEOUT:
                return _early_return(SOLVING_STATUS.TIMEOUT)
            elif r["status"] != SOLVING_STATUS.SUCCESS:
                return _early_return(r["status"])

            if r["satisfiability"]:
                last_sat = r
            else:
                # No feasible solution exists in the searched range.
                return _early_return(SOLVING_STATUS.SUCCESS)

        opt = _format_weight(W_MIN)
        return {
            "status": SOLVING_STATUS.SUCCESS,
            "objective_value": opt,
            "objective_bounds": (opt, opt),
            "assignment": last_sat["assignment"],
            "solve_time": time.perf_counter() - start_time,
            "trace": trace,
        }

    def solve_multiple(self, input_file, sum_arr_file, solve_range,
                       number_of_solutions, trail_vars=None,
                       precision=0, time_limit=None):
        r"""
        Find up to ``number_of_solutions`` distinct minimum-weight satisfying
        assignments by repeated solving with blocking clauses. Each iteration
        adds a clause excluding the previous assignment and writes the
        augmented CNF to a new file.

        Stops early if a solve fails or no satisfying assignment is found in
        the current range.

        INPUT:

            - ``input_file`` -- path to the base CNF
            - ``sum_arr_file`` -- path to the JSON file containing the sum
              array; see :meth:`solve`
            - ``solve_range`` -- ``(lower, upper)`` pair bounding the search
            - ``number_of_solutions`` -- maximum number of solutions to find
            - ``trail_vars`` -- optional iterable of CNF variable indices
              (ints) that define "the trail". When provided, the blocking
              clause is built only over these variables; assignments that
              differ only on helper variables are treated as the same
              solution. When ``None``, every variable in the assignment is
              used.
            - ``precision`` -- integer (default ``0``); see :meth:`solve`
            - ``time_limit`` -- float or ``None``; per-iteration time limit

        OUTPUT:

            - list of result dicts in the same shape as :meth:`solve` returns,
              ordered best (lowest weight) first
        """
        results = []
        cur = input_file
        for i in range(number_of_solutions):
            r = self.solve(cur, sum_arr_file, solve_range,
                           precision=precision, time_limit=time_limit)
            results.append(r)
            done = (r["status"] != SOLVING_STATUS.SUCCESS
                    or r["objective_value"] is None)
            if done or i == number_of_solutions - 1:
                break
            cur = self._exclude_assignment(
                cur, r["assignment"], trail_vars=trail_vars
            )
        return results

    def _exclude_assignment(self, input_file, assignment, trail_vars=None):
        r"""
        Write a copy of the CNF in ``input_file`` with one extra blocking
        clause that excludes ``assignment``. Returns the path of the new file.

        The blocking clause is the disjunction of the negated literals of the
        previous satisfying assignment. If ``trail_vars`` is provided, only
        variables whose CNF index is in ``trail_vars`` participate in the
        clause; helpers are ignored.
        """
        sat = DIMACS()
        sat.read(str(input_file))
        if trail_vars is not None:
            trail_vars = set(trail_vars)
            literals = [
                (-v if val == 1 else v)
                for v, val in assignment.items()
                if v in trail_vars
            ]
        else:
            literals = [
                (-v if val == 1 else v)
                for v, val in assignment.items()
            ]
        sat.add_clause(tuple(literals))
        new_file = input_file.parent / f"{input_file.stem}_excl{input_file.suffix}"
        sat.write(new_file)
        return new_file

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

            - ``assignment`` -- dictionary; the assignment of the variables in the solution. Empty if the problem is unsatisfiable
        """
        pass

    def _generate_constraints_sum_leq_int_LS24(self, sat, sum_arr, num):
        r"""
        Helper method to implement a sequential counter in SAT, in order to model
        the constraint :math:`sum(arr) \leq num` as a SAT-formula.
        The constraints are given in
        https://link.springer.com/chapter/10.1007/978-3-031-54776-8_14,
        section 3.4.

        .. NOTE::

            There is a typo in this paper, as the sum that we want to bound should
            go from :math:`0 \leq i \leq l-1` instead of :math:`l`.
            Therefore, the last constraint must be
            :math:`\bar{u_{l-1}} \lor \bar{a_{l-2, w-1}}` instead of
            :math:`\bar{u_{l}} \lor \bar{a_{l-1, w-1}}`.

        TESTS::

            sage: # optional - cryptominisat
            sage: from sage.sat.solvers.dimacs import DIMACS
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: from pathlib import Path
            sage: tmpdir = tempfile.mkdtemp()
            sage: path = Path(tmpdir)
            sage: for NUM_CLAUSES in range(1, 20):
            ....:   sat = DIMACS()
            ....:   for i in range(1, NUM_CLAUSES + 1): sat.add_clause((i,))
            ....:   for bound in range(NUM_CLAUSES + 4):
            ....:       new_sat = SOLVER.CRYPTOMINISAT._generate_constraints_sum_leq_int_LS24(
            ....:           sat, [(1, cl) for cl in range(1, NUM_CLAUSES+1)], bound
            ....:       )
            ....:       _ = new_sat.write(path / 'constraints.cnf')
            ....:       _ = SOLVER.CRYPTOMINISAT.invoke(
            ....:           path / 'constraints.cnf',
            ....:           path / 'constraints.sat',
            ....:           path / 'constraints.log',
            ....:       )
            ....:       with open(path /'constraints.sat') as f:
            ....:           status = f.readlines()[0].strip('\n')
            ....:           f.close()
            ....:       if status == 'SAT':
            ....:           if bound != NUM_CLAUSES:
            ....:               raise AssertionError(
            ....:                   "The constraints don't assert correct bound!")
            ....:           else: break
            sage: import shutil
            sage: shutil.rmtree(tmpdir)

        If everything works correctly, then a constraint system which requires
        :math:`w` many variables to be SAT only becomes possible to solve if we
        append constraints that bound the weight to at least :math:`w`.
        This is exactly what is checked in the doctests above.
        """
        new_sat = DIMACS()
        for _ in range(sat.nvars()):
            new_sat.var()  # set counter to ``sat.nvars()``
        assert sat.nvars() == new_sat.nvars()

        for clause in sat.clauses():  # copy clauses
            new_sat.add_clause(clause[0])

        # instead of e.g. [(3, 124), (2, 158)], we have [124, 124, 124, 158, 158]
        u = []
        for arr_with_mults in [factor*[entry] for factor, entry in sum_arr]:
            u += arr_with_mults

        L = len(u)

        # special, trivial case for sum_arr with less elements than bound
        if L <= num:
            return new_sat

        # special, trivial case for w = 0
        if num == 0:
            for i in range(L):
                new_sat.add_clause((-u[i], ))
            return new_sat

        # auxilary vars a_{i,j}
        a = [[new_sat.var() for _ in range(num)] for _ in range(L)]

        new_sat.add_clause((-u[0], a[0][0]))
        for j in range(1, num):
            new_sat.add_clause((-a[0][j], ))
        for i in range(1, L-1):
            new_sat.add_clause((-u[i], a[i][0]))
            new_sat.add_clause((-a[i-1][0], a[i][0]))
            for j in range(1, num):
                new_sat.add_clause((-u[i], -a[i-1][j-1], a[i][j]))
                new_sat.add_clause((-a[i-1][j], a[i][j]))
            new_sat.add_clause((-u[i], -a[i-1][num-1]))
        new_sat.add_clause((-u[L-1], -a[L-2][num-1]))

        return new_sat

class LOGIC_MINIMIZER_CVL(SOLVER_CVL, ABC):
    """
    Abstract base class for implementing an interface to a logic minimizer.

    Logic minimizers expose only :meth:`invoke`; there is no high-level
    ``solve`` operation because they don't search for an optimum.
    """
    def __init__(self):
        """Initizialize the minimizer interface."""
        super().__init__()


class GUROBI_CVL(MILP_SOLVER_CVL):
    """
    Interface to the Gurobi MILP solver, see https://www.gurobi.com/.

    See :class:`civerly.solvers.SCIP_CVL` for examples.
    """
    def __init__(self):
        """Initizialize the Gurobi interface."""
        super().__init__()
        self.name = "Gurobi"
        self.timeout_string = r"Time limit reached"
        self.bounds_regexp = r'Best objective (\S+), best bound (\S+), gap'

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

            - ``assignment`` -- dictionary; the assignment of the variables in the solution
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

    def solve_multiple(self, input_file, milp, number_of_solutions,
                       trail_vars=None, time_limit=None):
        r"""
        Find the ``number_of_solutions`` best solutions to the model using
        Gurobi's solution pool. ``milp`` and ``trail_vars`` are accepted to
        match the base signature but are unused: the pool produces all
        solutions in a single invocation, and Gurobi's CLI does not expose a
        "distinct only over these variables" knob -- the pool's distinctness
        criterion is over full assignments (helpers included).

        Gurobi pool parameters used:

        - ``PoolSolutions=n``: keep at most *n* solutions.
        - ``PoolSearchMode=2``: systematically enumerate pool solutions.
        - ``PoolGap=0``: only accept solutions matching the optimum.
        - ``SolFiles=<prefix>``: write pool solutions as ``<prefix>0.sol``, ``<prefix>1.sol``, ...

        .. SEEALSO::

            :meth:`civerly.solvers.MILP_SOLVER_CVL.solve_multiple`

        TODO: add examples for solve_multiple here
        """
        raise NotImplementedError
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

    EXAMPLES:

        Solve a model for the AES::

            sage: # optional - scip
            sage: from civerly.cipher_implementations.aes import AES_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip # random
            ....:   aes = AES_CVL(R=10)
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.MILP,
            ....:       granularity=GRANULARITY.WORDWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.BRANCH_NUMBER,
            ....:       milp_solver=SOLVER.SCIP,
            ....:       path=Path(tmpdir))
            ....:   aes.model(model_options)
            ....:   SOLVER.SCIP.solve(model_options.path / "AES.mps")
            2884 variables and 3085 constraints were written to ...
            Boolean Program (minimization, 2884 variables, 3085 constraints)
            {'status': <SOLVING_STATUS.SUCCESS: 1>,
             'objective_value': 55,
             'objective_bounds': (55, 55),
             'assignment': {'OUT': {13: 0,
            ...
               2: 0},
              'X0': {1: 0,
            ...
               30: 0},
            ...
              'X12': {1: 0,
            ...
               31: 0,
               30: 0},
              'IN': {0: 0,
            ...
               15: 0}},
             'solve_time': 0.2824276300088968}

        Solve a model for CRAFT with a time limit (the identified solution is non-optimal)::

            sage: from civerly.cipher_implementations.craft import CRAFT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: craft = CRAFT_CVL(15)
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip # random
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     path=Path(tmpdir))
            ....:   craft.model(model_options)
            ....:   SOLVER.SCIP.solve(model_options.path / "CRAFT.mps", time_limit=5)
            8736 variables and 9021 constraints were written to ...
            Boolean Program (minimization, 8736 variables, 9021 constraints)
            {'status': <SOLVING_STATUS.TIMEOUT: 2>,
             'objective_value': 73,
             'objective_bounds': (34.3498121721, 73),
             'assignment': {'OUT': {2: 0,
            ...
            'solve_time': 5.063110857998254}
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

            - ``assignment`` -- dictionary; the assignment of the variables in the solution
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

    See :class:`civerly.solvers.SCIP_CVL` for examples.
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

            - ``assignment`` -- dictionary; the assignment of the variables in the solution
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

    EXAMPLES:

        Solve a model for PRESENT::

            sage: # optional - cryptominisat  # optional - espresso
            sage: from civerly.cipher_implementations.present import PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir: # random
            ....:   present_cipher = PRESENT_CVL(R=4)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   _ = present_cipher.model(model_options)
            ....:   SOLVER.CRYPTOMINISAT.solve(
            ....:     model_options.path / "PRESENT.cnf",
            ....:     model_options.path / "PRESENTsum.json",
            ....:     model_options.solve_range,
            ....:     model_options.sat_precision)
            5312 variables and 12993 clauses were written to ...
            {'status': <SOLVING_STATUS.SUCCESS: 1>,
             'objective_value': 6,
             'objective_bounds': (6, 6),
             'assignment': {1: 0,
              2: 0,
              3: 0,
            ...
              6464: 0},
            'solve_time': 1.5007964510004967,
            'trace': {
             50: {'status': <SOLVING_STATUS.SUCCESS: 1>,
              'satisfiability': True,
              'assignment': ...
              'solve_time': 0.30154894801671617},
             25: {'status': <SOLVING_STATUS.SUCCESS: 1>,
              'satisfiability': True,
              'assignment': ...
              'solve_time': 0.28024723200360313},
             12: {'status': <SOLVING_STATUS.SUCCESS: 1>,
              'satisfiability': True,
              'assignment': ...
              'solve_time': 0.1579511149902828},
             6: {'status': <SOLVING_STATUS.SUCCESS: 1>,
              'satisfiability': True,
              'assignment': ...
              'solve_time': 0.12510626600123942},
             3: {'status': <SOLVING_STATUS.SUCCESS: 1>,
              'satisfiability': False,
              'assignment': {},
              'solve_time': 0.16972918799729086},
             5: {'status': <SOLVING_STATUS.SUCCESS: 1>,
              'satisfiability': False,
              'assignment': {},
              'solve_time': 0.26149826901382767}}}

        Again, but this time more rounds and with a timeout (which finds a non-optimal solution)::

            sage: # optional - cryptominisat  # optional - espresso
            sage: from civerly.cipher_implementations.present import PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir: # random
            ....:   present_cipher = PRESENT_CVL(R=13)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   _ = present_cipher.model(model_options)
            ....:   SOLVER.CRYPTOMINISAT.solve(
            ....:     model_options.path / "PRESENT.cnf",
            ....:     model_options.path / "PRESENTsum.json",
            ....:     model_options.solve_range,
            ....:     model_options.sat_precision,
            ....:     time_limit=5)
            16112 variables and 40209 clauses were written to ...
            {'status': <SOLVING_STATUS.TIMEOUT: 2>,
             'objective_value': 25,
             'objective_bounds': (13, 25),
             'assignment': ...
            ...
            'solve_time': 5.105086910014506,
            'trace': ...
            ...
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

            - ``assignment`` -- dictionary; the assignment of the variables in the solution. Empty if the problem is unsatisfiable
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

    See :class:`civerly.solvers.CRYPTOMINISAT_CVL` for examples.
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

            - ``assignment`` -- dictionary; the assignment of the variables in the solution. Empty if the problem is unsatisfiable
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

    TODO: add examples for invoke; complete docstrings
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
        ``time_limit`` parameter is ignored. If ``solution_file`` already
        exists, the call is a no-op (cache hit).

        .. SEEALSO::

            :meth:`civerly.solvers.SOLVER_CVL.invoke`
        """
        self._check_can_invoke(input_file, solution_file, log_file)
        if solution_file.exists():
            print(
                f"Using existing file {solution_file}, "
                "make sure it is up to date!"
            )
            return SOLVING_STATUS.SUCCESS
        command = self._build_command(input_file, solution_file, log_file, time_limit)
        with solution_file.open('a') as redirect:
            errno = subprocess.Popen(
                command, stdout=redirect, stderr=redirect
            ).wait()
        return self.errno_map.get(errno, SOLVING_STATUS.ERROR)

    def _build_command(self, input_file, solution_file, log_file, time_limit):
        """Build the Espresso CLI command list."""
        return ["espresso", "-epos", str(input_file)]


class EXTERNAL_MILP_SOLVER_CVL(MILP_SOLVER_CVL):
    """
    Interface for external MILP solver.

    EXAMPLES:

        Simulate external MILP solver::

            sage: # optional - scip
            sage: from civerly.cipher_implementations.aes import AES_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: aes = AES_CVL(R=10)
            sage: tmpdir = tempfile.mkdtemp()
            sage: model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.WORDWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE,
            ....:     milp_solver=None,
            ....:     path=Path(tmpdir))
            sage: aes.analyse(model_options)
            Traceback (most recent call last):
            ...
            civerly.solvers.ExternalSolveRequired: ExternalMILPSolver:
            solve ... externally and place the result at ..., then re-run.
            sage: SOLVER.SCIP.invoke(
            ....:     model_options.path / "MixColumn51845.mps",
            ....:     model_options.path / "MixColumn51845.0ea31e4f.sol",
            ....:     model_options.path / "MixColumn51845.log")
            <SOLVING_STATUS.SUCCESS: 1>
            sage: aes.analyse(model_options)
            Traceback (most recent call last):
            ...
            civerly.solvers.ExternalSolveRequired: ExternalMILPSolver:
            solve ... externally and place the result at ..., then re-run.
            sage: SOLVER.SCIP.invoke(
            ....:     model_options.path / "AES.mps",
            ....:     model_options.path / "AES.216bd044.sol",
            ....:     model_options.path / "AES.log")
            <SOLVING_STATUS.SUCCESS: 1>
            sage: aes.analyse(model_options)
            Using existing MILP model, make sure it is up to date!
            2848 variables and 2977 constraints were written to ...
            Using existing file ..., make sure it is up to date!
            55
            sage: import shutil
            sage: shutil.rmtree(tmpdir)
    """
    def __init__(self):
        """Initizialize the interface."""
        super().__init__()
        self.name = "ExternalMILPSolver"

    def invoke(self, input_file, solution_file, log_file, time_limit=None):
        """
        Signal that the user must solve the MILP externally.

        If ``solution_file`` already exists (e.g. the user provided it before
        re-running), this is a no-op. Otherwise, an :class:`ExternalSolveRequired`
        exception is raised carrying the input and expected output paths.

        INPUT:

            - ``input_file``-- path to the file containing the model

            - ``solution_file``-- path where the user must place the solution

            - ``log_file``-- path to the solver's log file

            - ``time_limit``-- float (default ``None``); ignored

        OUTPUT:

            - :attr:`SOLVING_STATUS.SUCCESS` when ``solution_file`` is present
        """
        self._check_can_invoke(input_file, solution_file, log_file)
        if solution_file.exists():
            return self._check_timeout(log_file, None, SOLVING_STATUS.SUCCESS)
        raise ExternalSolveRequired(
            f"{self.name}: solve {input_file} externally and place the "
            f"result at {solution_file}, then re-run."
        )

    def _process_solution_file(self, solution_file):
        """
        Extract the objective value and the variable assignment of the solution.

        INPUT:

            - ``solution_file``-- path to the file containing the solution

        OUTPUT:

            - ``objective_value`` -- float; the objective value of the solution

            - ``assignment`` -- dictionary; the assignment of the variables in the solution
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
        regexps =  [
            SOLVER.SCIP.bounds_regexp,
            SOLVER.GUROBI.bounds_regexp,
            SOLVER.GLPK.bounds_regexp,
            ]
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message=r"No objective bounds found in .*")
            for regexp in regexps:
                self.bounds_regexp = regexp
                lower, upper = super()._get_objective_bounds(log_file)
                if (lower, upper) != (None, None):
                    return lower, upper
        warnings.warn(f"No objective bounds found in {log_file}")
        return None, None

    def _build_command(self, input_file, solution_file, log_file, time_limit):
        """Unused: :meth:`invoke` and never runs a subprocess."""
        raise NotImplementedError(
            "The external MILP solver is not invoked by CiVerLy."
        )

    def _check_timeout(self, log_file, time_limit, status):
        """
        Check the log file for a timeout report and update ``status`` accordingly.

        ``log_file`` is searched for all known ``timeout_string`` and ``SOLVING_STATUS.TIMEOUT`` is returned on a hit.

        INPUT:

            - ``log_file`` -- path to the log file
            - ``time_limit``; ignored
            - ``status`` -- the current :class:`SOLVING_STATUS`

        OUTPUT:

            - the (possibly updated) :class:`SOLVING_STATUS`
        """
        timeout_strings = [
            SOLVER.SCIP.timeout_string,
            SOLVER.GUROBI.timeout_string,
            SOLVER.GLPK.timeout_string,
        ]
        for timeout_string in timeout_strings:
            self.timeout_string = timeout_string
            status = super()._check_timeout(log_file, 0, status)
        return status


class EXTERNAL_SAT_SOLVER_CVL(SAT_SOLVER_CVL):
    """
    Interface for external SAT solver.

    TODO: add example
    """

    def __init__(self):
        """Initizialize the interface."""
        super().__init__()
        self.name = "ExternalSATSolver"

    def invoke(self, input_file, solution_file, log_file, time_limit=None):
        """
        Signal that the user must solve the SAT externally.

        If ``solution_file`` already exists (e.g. the user provided it before
        re-running), this is a no-op. Otherwise, an :class:`ExternalSolveRequired`
        exception is raised carrying the input and expected output paths.

        INPUT:

            - ``input_file``-- path to the file containing the model

            - ``solution_file``-- path where the user must place the solution

            - ``log_file``-- path to the solver's log file

            - ``time_limit``-- float (default ``None``); ignored

        OUTPUT:

            - :attr:`SOLVING_STATUS.SUCCESS` when ``solution_file`` is present
        """
        self._check_can_invoke(input_file, solution_file, log_file)
        if solution_file.exists():
            return SOLVING_STATUS.SUCCESS
        raise ExternalSolveRequired(
            f"{self.name}: solve {input_file} externally and place the "
            f"result at {solution_file}, then re-run."
        )


    def _process_solution_file(self, solution_file):
        """
        Extract the satisfiability and the variable assignment of the solution.

        INPUT:

            - ``solution_file``-- path to the file containing the solution

        OUTPUT:

            - ``satisfiability`` -- bool

            - ``assignment`` -- dictionary; the assignment of the variables in the solution. Empty if the problem is unsatisfiable
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
        """Unused: :meth:`invoke` and never runs a subprocess."""
        raise NotImplementedError(
            "The external SAT solver is not invoked by CiVerLy."
        )


class EXTERNAL_LOGIC_MINIMIZER_CVL(LOGIC_MINIMIZER_CVL):
    """
    Interface for external logic minimizer.

    EXAMPLES:

        Simulate external Espresso minimization::

            sage: # optional - cryptominisat  # optional - espresso
            sage: from civerly.cipher_implementations.gift import GIFT_CVL
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: tmpdir = tempfile.mkdtemp()
            sage: gift_cipher = GIFT_CVL(R=2)
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:   solve_range=(0, 10),
            ....:   sat_precision=1,
            ....:   sat_solver=SOLVER.CRYPTOMINISAT,
            ....:   logic_minimizer=None,
            ....:   path=Path(tmpdir))
            sage: gift_cipher.analyse(model_options)
            Traceback (most recent call last):
            ...
            civerly.solvers.ExternalSolveRequired: ExternalLogicMinimizer:
            minimize ... externally and place the result at ..., then re-run.
            sage: SOLVER.ESPRESSO.invoke(
            ....:     model_options.path / "espresso-d1bda7a_in.pla",
            ....:     model_options.path / "espresso-d1bda7a_out.pla",
            ....:     model_options.path / "espresso-d1bda7a_out.log")
            <SOLVING_STATUS.SUCCESS: 1>
            sage: gift_cipher.analyse(model_options)
            2560 variables and 6401 clauses were written to '...'
            3.4
            sage: import shutil
            sage: shutil.rmtree(tmpdir)
    """
    def __init__(self):
        """Initizialize the interface."""
        super().__init__()
        self.name = "ExternalLogicMinimizer"

    def invoke(self, input_file, solution_file, log_file, time_limit=None):
        """
        Signal that the user must minimize the input externally.

        If ``solution_file`` already exists (e.g. the user provided it before
        re-running), this is a no-op. Otherwise, an :class:`ExternalSolveRequired`
        exception is raised carrying the input and expected output paths.

        INPUT:

            - ``input_file``-- path to the file containing the model

            - ``solution_file``-- path where the user must place the output

            - ``log_file``-- path to the solver's log file

            - ``time_limit``-- float (default ``None``); ignored

        OUTPUT:

            - :attr:`SOLVING_STATUS.SUCCESS` when ``solution_file`` is present
        """
        self._check_can_invoke(input_file, solution_file, log_file)
        if solution_file.exists():
            return SOLVING_STATUS.SUCCESS
        raise ExternalSolveRequired(
            f"{self.name}: minimize {input_file} externally and place the "
            f"result at {solution_file}, then re-run."
        )

    def _build_command(self, input_file, solution_file, log_file, time_limit):
        """Unused: :meth:`invoke` and never runs a subprocess."""
        raise NotImplementedError(
            "The external logic minimizer is not invoked by CiVerLy."
        )


class SOLVER:
    """
    Registry of pre-instantiated solver objects, ready to use in
    :class:`civerly.model_options.MODEL_OPTIONS`.

    Each attribute is a single shared instance; instantiate the corresponding
    class directly (e.g. ``SCIP_CVL()``) if you need a separate one.
    """
    SCIP = SCIP_CVL()
    GLPK = GLPK_CVL()
    GUROBI = GUROBI_CVL()
    CRYPTOMINISAT = CRYPTOMINISAT_CVL()
    CADICAL = CADICAL_CVL()
    ESPRESSO = ESPRESSO_CVL()
    EXTERNAL_MILP_SOLVER = EXTERNAL_MILP_SOLVER_CVL()
    EXTERNAL_SAT_SOLVER = EXTERNAL_SAT_SOLVER_CVL()
    EXTERNAL_LOGIC_MINIMIZER = EXTERNAL_LOGIC_MINIMIZER_CVL()
