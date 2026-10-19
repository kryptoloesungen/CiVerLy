import json
from abc import ABC, abstractmethod
from pathlib import Path

from sage.numerical.mip import MixedIntegerLinearProgram
from sage.sat.solvers.dimacs import DIMACS

from civerly.util import translate_milp_constraint


class Problem_CVL(ABC):
    r"""
    Abstract parent class of :class:`MILP_CVL` and :class:`SAT_CVL`, holding
    everything both kinds of problems have in common:

    - the variable bookkeeping (``vars``, ``VAR_IN``, ``VAR_OUT``,
      ``VAR_MODEL``, :meth:`get_var`),

    - the JSON serialization (:meth:`dump`, :meth:`load`) and the comparison
      of problems, both built upon :meth:`to_dict` and :meth:`from_dict`,

    - incorporating one problem into another one (:meth:`append`).

    Subclasses inherit from ``Problem_CVL`` *first* and from the SageMath
    class they wrap second, so that :meth:`__init__` is passed on to the
    latter. They have to implement

    - the common interface :meth:`number_of_variables`,
      :meth:`number_of_constraints` and :meth:`write`,

    - the serialization :meth:`to_dict` and :meth:`from_dict`, for which
      :meth:`_variables_to_list` and :meth:`_restore_variables` take care of
      the variables,

    - the hooks :meth:`_new_variable`, :meth:`_backend_indices`,
      :meth:`_constraints` and :meth:`_add_translated_constraint`.

    A variable returned by :meth:`new_variable` behaves like a dictionary
    whose components are created lazily on first access, and has to provide
    the method ``get_index(key)``, returning the backend index of the
    component ``key``, as well as the attribute ``type``, an index into
    :attr:`VAR_TYPES`.
    """

    # The types a variable can have. A variable stores the index of its type.
    VAR_TYPES = ("real", "binary", "integer", "nonnegative")

    def __init__(self, *args, **kwargs):
        """
        Initialize the wrapped SageMath class with ``args`` and ``kwargs``,
        and set up the attributes shared by all problems:

        - ``vars`` -- dict[str -> variable]; Stores all variables created by :meth:``self.new_variable``.

        - ``VAR_IN``, ``VAR_OUT`` -- variable; The input and output variables.

        - ``VAR_MODEL`` -- list[variable]; The standard variable to be used for modeling.
        """
        super().__init__(*args, **kwargs)
        self._vars = {}
        self._var_by_index = {}

        self.VAR_IN = self.new_variable(name="IN", binary=True)
        self.VAR_OUT = self.new_variable(name="OUT", binary=True)
        self.VAR_MODEL = None

    def __eq__(self, other):
        """
        Compare two problems of the same type with each other by considering
        the corresponding dictionaries (see :meth:``to_dict``).
        Comparing the wrapped SageMath objects considers the objects
        themselves, not whether the problems they represent are actually
        equal, which is done here.

        TESTS:

            sage: import tempfile
            sage: from civerly.problem import MILP_CVL
            sage: milp = MILP_CVL()
            sage: x = milp.new_variable(name="x")
            sage: milp.add_constraint(6*x[0] + 4*x[1] <= 1)
            sage: milp.add_constraint(x[0] + 2*x[2] >= 3)
            sage: milp.add_constraint(x[0] - x[1] - 3*x[2] >= 3)
            sage: milp.set_objective(3*x[1] - 2*x[2])
            sage: with tempfile.NamedTemporaryFile() as f:
            ....:   milp.dump(f.name)
            ....:   milp2 = MILP_CVL.load(f.name)
            ....:   milp == milp2
            True

        Again with an actual ``MILP_CVL`` coming from a CiVerLy modeling:

            sage: from civerly.problem import MILP_CVL
            sage: from civerly.cipher_implementations.present \
            ....:   import PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: present_cipher = PRESENT_CVL(R=4)
            sage: # optional - scip, espresso
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   present_cipher.analyse(model_options)
            5312 variables and 8641 constraints were written to...
            12
            sage: milp = present_cipher.milp
            sage: with tempfile.NamedTemporaryFile() as f:
            ....:   milp.dump(f.name)
            ....:   milp2 = MILP_CVL.load(f.name)
            ....:   milp == milp2
            True

        The same for a ``SAT_CVL``::

            sage: import tempfile
            sage: from civerly.problem import SAT_CVL
            sage: sat = SAT_CVL()
            sage: x = sat.new_variable(name="x")
            sage: sat.add_clause((x[0], -x[1]))
            sage: sat.add_clause((-x[0], x[2]))
            sage: with tempfile.NamedTemporaryFile() as f:
            ....:   sat.dump(f.name)
            ....:   sat2 = SAT_CVL.load(f.name)
            ....:   sat == sat2
            True
            sage: sat.add_clause((x[1], x[2]))
            sage: sat == sat2
            False
        """
        if type(other) is not type(self):
            return False
        return self.to_dict() == other.to_dict()

    @property
    def vars(self):
        """
        A dictionary containing all the variables added via :meth:``new_variable``.
        """
        return self._vars

    def get_var(self, index):
        """
        Return the variable whose backend index is ``index``.

        The lookup is served from a cache mapping backend indices to variables,
        which is (re)built whenever ``index`` is missing from it. Rebuilding is
        the only way to pick up variables that were created in the meantime, as
        the components of a variable are created lazily. A cached entry never
        goes stale, since the backend index of a variable never changes.

        TESTS:

        Variables created after the cache was built are still found::

            sage: from civerly.problem import MILP_CVL
            sage: milp = MILP_CVL()
            sage: x = milp.new_variable(name="x", binary=True)
            sage: x[0], x[1]
            (x_0, x_1)
            sage: milp.get_var(0) is x[0]
            True
            sage: x[2]
            x_2
            sage: milp.get_var(2) is x[2]
            True
            sage: milp.get_var(3)
            Traceback (most recent call last):
            ...
            AssertionError: var not found
        """
        if index not in self._var_by_index:
            for var in self.vars.values():
                for i, b_var in var.items():
                    self._var_by_index[var.get_index(i)] = b_var
        if index not in self._var_by_index:
            raise AssertionError("var not found")
        return self._var_by_index[index]

    def new_variable(self, *args, **kwargs):
        """
        Create a new variable via :meth:`_new_variable` and store it inside
        ``self.vars`` under its name, given as keyword argument ``name``.
        """
        var = self._new_variable(*args, **kwargs)
        self._vars[kwargs.get("name")] = var
        return var

    @abstractmethod
    def _new_variable(self, *args, **kwargs):
        """
        Create and return a new variable, see :meth:`new_variable`.
        """

    def dump(self, filename):
        """
        Serialize ``self`` into a dictionary using :meth:`to_dict`,
        and write to ``filename`` afterwards. Takes the parameter:

        - filename -- str; The json filename to dump ``self`` into.
        """
        with Path(filename).open("w") as f:
            json.dump(self.to_dict(), fp=f)
        return

    @classmethod
    def load(cls, filename):
        """
        Load the problem from a json file, using :meth:``from_dict``.

        TESTS::

        Dumping the MILP from a previous analysis, loading it and solving it
        shall result in the exact same solution (when solving process
        is deterministic):

            sage: from civerly.problem import MILP_CVL
            sage: from civerly.cipher_implementations.gift import GIFT64_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: gift = GIFT64_CVL(R=3)
            sage: # optional - scip espresso
            sage: with tempfile.TemporaryDirectory(delete=False) as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     milp_solver=SOLVER.SCIP,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   gift.analyse(model_options)
            2880 variables and 5313 constraints were written to...
            7
            sage: gift.milp.dump(model_options.path / "milp.json")
            sage: from civerly.problem import MILP_CVL
            sage: from civerly.solvers import SCIP_CVL
            sage: milp = MILP_CVL.load(model_options.path / "milp.json")
            sage: milp.write_mps(str(model_options.path / "milp.mps"))
            Writing problem data to ...
            18970 records were written
            sage: # optional - scip
            sage: scip = SCIP_CVL()
            sage: result = scip.solve(model_options.path / "milp.mps")
            sage: result['assignment'] == gift.result['assignment']
            True
            sage: import shutil
            sage: shutil.rmtree(model_options.path, ignore_errors=True)
        """
        with Path(filename).open() as f:
            data = json.load(f)
        return cls.from_dict(data)

    @abstractmethod
    def number_of_variables(self):
        """
        Return the number of variables of ``self``.
        """
        pass

    @abstractmethod
    def number_of_constraints(self):
        """
        Return the number of constraints of ``self``.
        """
        pass

    @abstractmethod
    def write(self, filename):
        """
        Write ``self`` to ``filename``, in the format the solvers expect.
        """
        pass

    @abstractmethod
    def to_dict(self):
        """
        Return a json-serializable dictionary describing ``self`` completely.
        """
        pass

    def _variables_to_list(self):
        """
        Return the entry ``variables`` of :meth:`to_dict`: a list of the form
        ``[(name, index, backend_index, var_type)]``, where:

        - ``name`` -- string; The name of the variable.

        - ``index`` -- int; The index of this component inside the variable
          (recall, variables are dictionaries).

        - ``backend_index`` -- int; The backend index of this component.

        - ``var_type`` -- int; The index of the type of the variable inside
          :attr:`VAR_TYPES`.

        EXAMPLE::

            sage: from civerly.problem import MILP_CVL, SAT_CVL
            sage: milp = MILP_CVL()
            sage: x = milp.new_variable(name="x", integer=True)
            sage: milp.add_constraint(x[3] + milp.VAR_IN[0] <= 1)
            sage: milp._variables_to_list()
            [('IN', 0, 1, 1), ('x', 3, 0, 2)]
            sage: sat = SAT_CVL()
            sage: x = sat.new_variable(name="x")
            sage: sat.add_clause((x[3], sat.VAR_IN[0]))
            sage: sat._variables_to_list()
            [('IN', 0, 2, 1), ('x', 3, 1, 1)]
        """
        return [
            (name, int(index), int(var.get_index(index)), var.type)
            for name, var in self.vars.items()
            for index in list(var.keys())
        ]

    def _restore_variables(self, variables):
        """
        Recreate the variables given by ``variables``, the output of
        :meth:`_variables_to_list`, in ``self``, which is used by
        :meth:`from_dict`. This sets ``VAR_IN``, ``VAR_OUT`` and
        ``VAR_MODEL`` accordingly.

        The components are created in the order of their backend indices, so
        that they implicitly get the same backend indices again. Backend
        indices which do not belong to any variable are skipped by means of
        :meth:`_skip_backend_indices`.
        """
        self.VAR_MODEL = []
        restored = {}
        for name, index, backend_index, var_type in sorted(
            variables, key=lambda x: x[2]
        ):
            if name not in restored:
                kwargs = {"name": name, self.VAR_TYPES[var_type]: True}
                restored[name] = self.new_variable(**kwargs)
                if name == "IN":
                    self.VAR_IN = restored[name]
                elif name == "OUT":
                    self.VAR_OUT = restored[name]
                else:
                    self.VAR_MODEL.append(restored[name])

            self._skip_backend_indices(backend_index)
            # indexing creates the component, as they are created lazily
            restored[name][index]

    def _skip_backend_indices(self, backend_index):  # noqa: B027
        """
        Make sure that the next component being created gets the backend
        index ``backend_index``. Nothing has to be done, unless there are
        backend variables which do not belong to any variable of ``self``.
        """

    @classmethod
    @abstractmethod
    def from_dict(cls, data):
        """
        Reconstruct a problem from the output of :meth:``to_dict``.
        """

    def append(self, other, var):
        r"""
        Incorporate the problem ``other`` into ``self``, by copying every
        variable of ``other`` into the namespace of the variable ``var`` and
        adding all constraints of ``other`` in terms of these new variables.

        The backend index a variable has in ``other`` is used as the *key*
        under which its counterpart is created in ``var``. Since the
        constraints of ``other`` refer to their variables by exactly these
        indices, translating them is a mere lookup in ``var``.

        For a ``MILP_CVL``, the objective function of ``other`` is ignored.

        INPUT:

          - ``other`` -- problem of the same type as ``self``; the problem to
            append

          - ``var`` -- variable of ``self``, as returned by
            :meth:`new_variable`; the namespace the variables of ``other`` are
            copied into. It must not be used for anything else, as its keys are
            dictated by ``other``.

        OUTPUT:

        A dict mapping the backend index of each variable created in ``self``
        to the backend index of its counterpart in ``other``.

        EXAMPLE:

        Append a small milp to one that already holds a variable, so that the
        indices of the two differ::

            sage: from civerly.problem import MILP_CVL
            sage: other = MILP_CVL()
            sage: x = other.new_variable(name="x", binary=True)
            sage: other.add_constraint(x[0] + 2*x[1] <= 1)
            sage: other.to_dict()['constraints']
            [[(0, 1), (1.0, 2.0), [None, 1.0]]]
            sage: milp = MILP_CVL()
            sage: milp.add_constraint(milp.VAR_IN[0] <= 1)
            sage: X0 = milp.new_variable(name="X0", binary=True)
            sage: milp.append(other, X0)
            {1: 0, 2: 1}

        The appended constraint refers to the variables of ``milp``, the
        returned dict tells which variable of ``other`` each of them
        corresponds to::

            sage: milp.to_dict()['constraints']
            [[(0,), (1.0,), [None, 1.0]], [(1, 2), (1.0, 2.0), [None, 1.0]]]

        Appending the same milp twice under different namespaces duplicates it,
        which is how a component that is used more than once is modeled only
        once::

            sage: X1 = milp.new_variable(name="X1", binary=True)
            sage: milp.append(other, X1)
            {3: 0, 4: 1}
            sage: milp.number_of_constraints()
            3

        The same for a ``SAT_CVL``: Append a small sat to one that already
        holds a variable, so that the indices of the two differ::

            sage: from civerly.problem import SAT_CVL
            sage: other = SAT_CVL()
            sage: x = other.new_variable(name="x")
            sage: other.add_clause((x[0], -x[1]))
            sage: sat = SAT_CVL()
            sage: sat.add_clause((sat.VAR_IN[0],))
            sage: X0 = sat.new_variable(name="X0")
            sage: sat.append(other, X0)
            {2: 1, 3: 2}
            sage: sat.clauses()
            [((1,), False, None), ((2, -3), False, None)]

        Appending the same sat twice under different namespaces duplicates it::

            sage: X1 = sat.new_variable(name="X1")
            sage: sat.append(other, X1)
            {4: 1, 5: 2}
            sage: sat.number_of_constraints()
            3
        """
        translation = {}
        for other_index in other._backend_indices():
            # indexing ``var`` creates the corresponding variable in ``self``,
            # as the components of a variable are created lazily
            translation[var.get_index(other_index)] = other_index

        for constraint in other._constraints():
            self._add_translated_constraint(var, constraint)

        return translation

    @abstractmethod
    def _backend_indices(self):
        """
        Return the backend indices of all variables of ``self``, in the order
        in which :meth:`append` shall copy them.
        """

    @abstractmethod
    def _constraints(self):
        """
        Return all constraints of ``self``, in a form
        :meth:`_add_translated_constraint` understands.
        """

    @abstractmethod
    def _add_translated_constraint(self, var, constraint):
        """
        Add ``constraint``, an entry of the output of :meth:`_constraints` of
        another problem, to ``self``, replacing each of its variables by the
        component of ``var`` whose key is the backend index of that variable.
        """


class MILP_CVL(Problem_CVL, MixedIntegerLinearProgram):
    r"""
    Wrapper for SageMath's :class:``MixedIntegerLinearProgram``, supporting JSON
    serialization.

    EXAMPLE:

    ``MILP_CVL`` can be instantiated exactly like ``MixedIntegerLinearProgram``.

        sage: from civerly.problem import MILP_CVL
        sage: milp = MILP_CVL()
        sage: x = milp.new_variable(name="x")
        sage: milp.add_constraint(6*x[0] + 4*x[1] <= 1)
        sage: milp.add_constraint(x[0] + 2*x[2] >= 3)
        sage: milp.add_constraint(x[0] - x[1] - 3*x[2] >= 3)
        sage: milp.set_objective(3*x[1] - 2*x[2])
        sage: round(milp.solve())
        -9.0
        sage: [milp.backend.row(i) for i in range(milp.number_of_constraints())]
        [([1, 0], [4.0, 6.0]), ([2, 0], [-2.0, -1.0]), ([2, 1, 0], [3.0, 1.0, -1.0])]
        sage: [milp.backend.objective_coefficient(i) for i in range(milp.number_of_constraints())]
        [0.0, 3.0, -2.0]
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize :class:``MILP_CVL``. The process is almost identical to the initialization
        of SageMath's :class:``MixedIntegerLinearProgram`` except for the following points:

        - the solver argument is always set to "GLPK", as CiVerLy doesn't use it anyway.
          Instead, the external solvers specified by the model options are used (see ``solvers.py``).

        - New attributes, to make them easier to access (see :class:`Problem_CVL`):
            - ``vars`` -- dict[str -> MIPVariable]; Stores all MIPVariables created by :meth:``self.new_variable``.

            - ``VAR_IN``, ``VAR_OUT`` -- MIPVariable; The input and output variables.

            - ``VAR_MODEL`` -- list[MIPVariable]; The standard variable to be used for modeling.
        """
        # always default to glpk solver for sage wrapper to minimize dependencies
        kwargs.pop("solver", None)
        super().__init__(*args, solver="GLPK", **kwargs)
        self.backend = self.get_backend()

    def _new_variable(self, *args, **kwargs):
        """
        Create a MIPVariable via :meth:``MixedIntegerLinearProgram.new_variable``
        and store the MIPVariable type as its attribute, so that we can recover it
        when reconstructing it inside `from_dict`.

        There are four variable types:
        real (default), binary, integer, nonnegative.
        Setting them appropriately is crucial, as it would otherwise
        change the underlying MILP and its solution space completely.
        """
        var_types = [kwargs.get(var_type) for var_type in self.VAR_TYPES]
        # 'real' is the default
        var_type = var_types.index(True) if any(var_types) else 0

        var = MixedIntegerLinearProgram.new_variable(self, *args, **kwargs)
        # add new attributes + methods
        var.type = var_type
        var.get_index = lambda i: next(iter(var[i].dict().keys()))
        return var

    number_of_variables = MixedIntegerLinearProgram.number_of_variables
    number_of_constraints = MixedIntegerLinearProgram.number_of_constraints

    def write(self, filename):
        """
        Write ``self`` to the MPS file ``filename``, see
        :meth:``MixedIntegerLinearProgram.write_mps``.
        """
        self.write_mps(str(filename))

    def _backend_indices(self):
        """
        Return the backend indices of all variables, ordered by the
        MIPVariables they belong to.
        """
        return [
            var.get_index(key)
            for var in self.vars.values()
            for key in var.keys()  # noqa: SIM118
        ]

    def _constraints(self):
        """
        Return the constraints, see
        :meth:``MixedIntegerLinearProgram.constraints``.
        """
        return self.constraints()

    def _add_translated_constraint(self, var, constraint):
        """
        Add ``constraint`` in terms of the MIPVariable ``var``, see
        :func:`civerly.util.translate_milp_constraint`.
        """
        self.add_constraint(translate_milp_constraint(var, constraint))

    def to_dict(self):
        r"""
        Make ``MILP_CVL`` json-serializable by creating a dictionary with
        the following information:

        - maximization -- bool; Determines if the objective is to maximize or not.

        - variables -- list of the form ``[(name, index, backend_index, var_type)]``,
          see :meth:`_variables_to_list`. In the backend, the variables are of the
          form ``x_1234``, ``backend_index`` stores the integer 1234. ``var_type``
          indicates whether the MIPVariable is real (0), binary (1), integer (2),
          nonnegative (3).

        - objective -- list of floats, indexed by the variables list; contains the coefficients
          for the objective function. If we would have ``x[0] - 2*x[1] + x[3]``, the 'objective'
          list would be ``[1.0, -2.0, 0.0, 1.0]``.

        - constraints -- list of the form ``[[appearing_vars, coeffs, rhs]]``, where:
            - ``appearing_vars`` -- list of ints; the indices (under the variables list)
              of the variables appearing in this constraint.
            - ``coeffs`` -- list of floats; the corresponding coefficients of this constraint.
            - ``rhs`` -- list of two ints; represent the lower (index 0) and
              upper (index 1) bounds in this constraint.
            An example would look as follows:
            ``[..., [(611, 613, 614, 616, 617, 619), (-1.0, -1.0, 1.0, -1.0, -1.0, -1.0), [None, 0.0]], ...]``
            translates to the constraint :math:``-variables[611] - variables[613] + variables[614]
            - variables[616] - variables[617] - variables[619] \\leq 0``

        EXAMPLE::

            sage: from civerly.cipher_implementations.present \
            ....:   import PRESENT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: present_cipher = PRESENT_CVL(R=4)
            sage: # optional - espresso
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   present_cipher.model(model_options)
            5312 variables and 8641 constraints were written to ...
            sage: present_cipher.milp.to_dict()['variables']
            [('IN', 0, 5184, 1),
             ('IN', 1, 5185, 1),
             ('IN', 2, 5186, 1),
             ('IN', 3, 5187, 1),
             ('IN', 4, 5188, 1),
             ('IN', 5, 5189, 1),
             ('IN', 6, 5190, 1),
             ('IN', 7, 5191, 1),
             ('IN', 8, 5192, 1),
             ...
            sage: present_cipher.milp.to_dict()['objective']
            [0.0, 0.0, 0.0, 0.0, 0.0,...
            sage: present_cipher.milp.to_dict()['constraints']
            [[(0, 64), (-1.0, 1.0), [0.0, 0.0]],
             [(1, 65), (-1.0, 1.0), [0.0, 0.0]],
             [(2, 66), (-1.0, 1.0), [0.0, 0.0]],
             [(3, 67), (-1.0, 1.0), [0.0, 0.0]],
             [(4, 68), (-1.0, 1.0), [0.0, 0.0]],
             [(5, 69), (-1.0, 1.0), [0.0, 0.0]],
             [(6, 70), (-1.0, 1.0), [0.0, 0.0]],
             ...
        """
        return {
            "maximization": self.backend.is_maximization(),
            "variables": self._variables_to_list(),
            "objective": [
                float(self.backend.objective_coefficient(i))
                for i in range(self.number_of_variables())
            ],
            "constraints": [
                [
                    *zip(
                        *sorted(
                            zip(  # sort them with same permutation
                                list(map(int, self.backend.row(i)[0])),  # indices
                                list(map(float, self.backend.row(i)[1])),
                                strict=False,  # coeffs
                            )
                        ),
                        strict=False,
                    ),
                    [
                        float(e) if e is not None else None
                        for e in self.backend.row_bounds(i)
                    ],
                ]
                for i in range(self.number_of_constraints())
            ],
        }

    @classmethod
    def from_dict(cls, data):
        """
        Reconstruct a ``MILP_CVL`` from the output of :meth:``to_dict``,
        by building the variables, objective function, and constraints
        from the given dictionary ``data``.

        INPUT:
        - ``data`` -- dict; output of :meth:``to_dict``

        OUTPUT: A ``MILP_CVL`` object corresponding to ``data``

        EXAMPLE:

            sage: from civerly.cipher_implementations.craft \
            ....:   import CRAFT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: cipher = CRAFT_CVL(R=4)
            sage: # optional - espresso
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.MILP,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   cipher.model(model_options)
            10176 variables and 12929 constraints were written to...
            sage: data = cipher.milp.to_dict()
            sage: from civerly.problem import MILP_CVL
            sage: milp = MILP_CVL.from_dict(data)
            sage: milp == cipher.milp
            True
        """
        milp = cls(maximization=data["maximization"])
        milp._restore_variables(data["variables"])

        # rebuild objective
        obj = 0
        for var_id, coef in enumerate(data["objective"]):
            obj += coef * milp.get_var(var_id)

        milp.set_objective(obj)

        # reconstruct the constraints
        for indices, coefficients, (lower, upper) in data["constraints"]:
            expr = sum(
                coef * milp.get_var(var_id)
                for var_id, coef in zip(indices, coefficients, strict=False)
            )

            if lower is not None and upper is not None:
                if lower == upper:
                    milp.add_constraint(expr == lower)
                else:
                    milp.add_constraint(expr >= lower)
                    milp.add_constraint(expr <= upper)
            elif lower is not None:
                milp.add_constraint(expr >= lower)
            elif upper is not None:
                milp.add_constraint(expr <= upper)

        return milp


class SATVariable(dict):
    r"""
    The SAT counterpart of SageMath's ``MIPVariable``: a dictionary mapping
    keys to DIMACS variables (positive integers) of the :class:`SAT_CVL`
    ``sat``, where a variable is created via ``sat.var()`` the first time
    its key is accessed.

    EXAMPLE::

        sage: from civerly.problem import SAT_CVL
        sage: sat = SAT_CVL()
        sage: x = sat.new_variable(name="x")
        sage: x[5], x[0], x[5]
        (1, 2, 1)
        sage: -x[0]
        -2
        sage: x.get_index(0)
        2
    """

    def __init__(self, sat, name=None):
        super().__init__()
        self._sat = sat
        self.name = name
        # all SAT variables are boolean
        self.type = Problem_CVL.VAR_TYPES.index("binary")

    def __missing__(self, key):
        self[key] = self._sat.var()
        return self[key]

    def get_index(self, key):
        """
        Return the backend index of the component ``key``, which, for SAT, is
        the DIMACS variable itself.
        """
        return self[key]

    def __repr__(self):
        return f"SATVariable {self.name!r} of dimension 1"


class SAT_CVL(Problem_CVL, DIMACS):
    r"""
    Wrapper for SageMath's :class:``DIMACS``, supporting JSON
    serialization.

    EXAMPLE:

    ``SAT_CVL`` can be instantiated exactly like ``DIMACS``.

        sage: from civerly.problem import SAT_CVL
        sage: sat = SAT_CVL()
        sage: x = sat.new_variable(name="x")
        sage: sat.add_clause((x[0], -x[1]))
        sage: sat.add_clause((-x[0], x[2]))
        sage: sat.add_clause((x[1], -x[2]))
        sage: sat.clauses()
        [((1, -2), False, None), ((-1, 3), False, None), ((2, -3), False, None)]
        sage: (sat.number_of_variables(), sat.number_of_constraints())
        (3, 3)

    As for :class:``MILP_CVL``, the ``command`` argument of ``DIMACS`` is not
    used by CiVerLy. Instead, the external solvers specified by the model
    options are used (see ``solvers.py``). The attributes ``vars``,
    ``VAR_IN``, ``VAR_OUT`` and ``VAR_MODEL`` (see :class:`Problem_CVL`) hold
    :class:`SATVariable` objects.
    """

    def _new_variable(self, *args, **kwargs):
        """
        Create a new :class:`SATVariable`. Since all SAT variables are boolean,
        the type keywords of :meth:``MixedIntegerLinearProgram.new_variable``
        (real, binary, integer, nonnegative) are accepted for compatibility with
        :class:``MILP_CVL``, but ignored.
        """
        return SATVariable(self, name=kwargs.get("name"))

    def number_of_variables(self):
        """
        Return the number of variables, see :meth:``DIMACS.nvars``.
        """
        return self.nvars()

    def number_of_constraints(self):
        """
        Return the number of clauses.

        EXAMPLE:

            sage: import tempfile
            sage: from civerly.problem import SAT_CVL
            sage: sat = SAT_CVL()
            sage: x = sat.new_variable(name="x")
            sage: sat.add_clause((x[0], -x[1]))
            sage: sat.add_clause((-x[0], x[2]))
            sage: sat.number_of_constraints()
            2

        """
        return self._lit

    def write(self, filename=None):
        """
        Write ``self`` to the DIMACS file ``filename``, see
        :meth:``DIMACS.write``.
        """
        return DIMACS.write(self, None if filename is None else str(filename))

    def _backend_indices(self):
        """
        Return all DIMACS variables, not only those belonging to a
        SATVariable, as clauses may contain both.
        """
        return range(1, self.nvars() + 1)

    def _constraints(self):
        """
        Return the clauses as tuples of literals.
        """
        return [literals for literals, _, _ in self.clauses()]

    def _add_translated_constraint(self, var, constraint):
        """
        Add the clause ``constraint`` in terms of the SATVariable ``var``.
        """
        self.add_clause(
            tuple(var[lit] if lit > 0 else -var[-lit] for lit in constraint)
        )

    def _skip_backend_indices(self, backend_index):
        """
        Create DIMACS variables not belonging to any SATVariable, until the
        next variable being created is ``backend_index``.
        """
        while self.nvars() < backend_index - 1:
            self.var()

    def to_dict(self):
        r"""
        Make ``SAT_CVL`` json-serializable by creating a dictionary with
        the following information:

        - nvars -- int; The number of DIMACS variables. This also counts
          variables which do not belong to any SATVariable, e.g. those created
          by :meth:``var`` directly.

        - variables -- list of the form ``[(name, index, backend_index, var_type)]``,
          see :meth:`_variables_to_list`. ``backend_index`` is the corresponding
          DIMACS variable, and ``var_type`` is always 1 (binary).

        - clauses -- list of lists of ints; the clauses in DIMACS notation,
          e.g. ``[1, -2, 3]`` translates to the clause
          :math:``v_1 \\lor \\neg v_2 \\lor v_3``.

        EXAMPLE::

            sage: from civerly.problem import SAT_CVL
            sage: sat = SAT_CVL()
            sage: sat.add_clause((sat.VAR_IN[0], -sat.VAR_OUT[0]))
            sage: _ = sat.var()
            sage: x = sat.new_variable(name="x")
            sage: sat.add_clause((x[3], -x[1], sat.VAR_IN[1]))
            sage: sat.to_dict()['nvars']
            6
            sage: sat.to_dict()['variables']
            [('IN', 0, 1, 1), ('IN', 1, 6, 1), ('OUT', 0, 2, 1), ('x', 3, 4, 1), ('x', 1, 5, 1)]
            sage: sat.to_dict()['clauses']
            [[1, -2], [4, -5, 6]]
        """
        return {
            "nvars": int(self.nvars()),
            "variables": self._variables_to_list(),
            "clauses": [list(map(int, literals)) for literals, _, _ in self.clauses()],
        }

    @classmethod
    def from_dict(cls, data):
        """
        Reconstruct a ``SAT_CVL`` from the output of :meth:``to_dict``,
        by building the variables and clauses from the given dictionary ``data``.

        INPUT:
        - ``data`` -- dict; output of :meth:``to_dict``

        OUTPUT: A ``SAT_CVL`` object corresponding to ``data``

        EXAMPLE:

            sage: from civerly.problem import SAT_CVL
            sage: sat = SAT_CVL()
            sage: _ = sat.var()
            sage: x = sat.new_variable(name="x")
            sage: sat.add_clause((x[3], -x[1], sat.VAR_IN[0]))
            sage: sat.add_clause((7, -x[1]))
            sage: sat2 = SAT_CVL.from_dict(sat.to_dict())
            sage: sat2 == sat
            True
            sage: sat2.vars["x"][3]
            2

        A more complicated example::

            sage: # optional - cryptominisat espresso
            sage: from civerly.problem import SAT_CVL
            sage: from civerly.cipher_implementations.prince import PRINCE_CVL
            sage: from civerly.model_options import *
            sage: prince_cipher = PRINCE_CVL(R=4)
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     path=Path(tmpdir))
            ....:   sat = prince_cipher.model(model_options)
            4112 variables and 12081 clauses were written to ...
            sage: sat2 = SAT_CVL.from_dict(sat.to_dict())
            sage: sat2 == sat
            True
        """
        sat = cls()
        sat._restore_variables(data["variables"])
        # the trailing variables not belonging to any SATVariable
        sat._skip_backend_indices(data["nvars"] + 1)

        for clause in data["clauses"]:
            sat.add_clause(tuple(clause))

        return sat
