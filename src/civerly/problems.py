r"""
Abstractions for the modeling problems CiVerLy generates and solves.

A *problem* is the concrete optimization/decision model built for a cipher.
:class:`PROBLEM_CVL` is the abstract base class defining the interface every
problem type shares; a concrete subclass implements it for one kind of model.

The problem types currently provided are :class:`MILP_CVL` and
:class:`SAT_CVL`. A concrete subclass typically also inherits from an
underlying SageMath model class, so a problem object *is* that model while also
exposing the shared interface.
"""

import json
from abc import ABC, abstractmethod


class PROBLEM_CVL(ABC):
    r"""
    Abstract base class for a modeling problem.

    A concrete subclass represents one kind of model and implements the
    interface below, typically inheriting from an underlying SageMath model
    class so that the problem object *is* that model.

    Every problem has three kinds of variables: ``input_length`` input
    variables and ``output_length`` output variables (both given at
    construction), plus *model* variables added on demand via
    :meth:`new_variable`. All variables are enumerated; a variable is referred
    to by its integer index.

    Shared state, initialized here and populated by the subclasses / by
    :meth:`append`:

    - ``objective_terms`` -- list of ``(factor, var)`` pairs (``var`` an
      integer index) whose weighted sum is the *trail weight*, i.e. the
      quantity the problem optimizes for. How a concrete problem turns these
      terms into its objective or bound is up to the subclass. This is a
      generation-time helper consumed by :meth:`finish`; it is not part of the
      serialized form (see :meth:`to_dict`).
    - ``name_to_var`` / ``var_to_name`` -- the translation between a
      variable's name (``str``) and its enumerated index (``int``):
      ``name_to_var`` maps a name to its index, ``var_to_name`` the reverse.

    .. NOTE::

        Both :meth:`__eq__` and :meth:`__hash__` operate on the serialized
        content (:meth:`to_dict`): two problems are equal, and hash equally,
        when their serializations coincide.

    TESTS:

    :class:`PROBLEM_CVL` is abstract and cannot be instantiated directly::

        sage: from civerly.problems import PROBLEM_CVL
        sage: PROBLEM_CVL()
        Traceback (most recent call last):
        ...
        TypeError: Can't instantiate abstract class PROBLEM_CVL...
    """

    def __init__(self, input_length, output_length):
        r"""
        Initialize the shared problem state.

        Subclasses call ``super().__init__(input_length, output_length)``,
        then initialize the underlying Sage model and allocate the input and
        output variables (from their lengths) and any model variables (via
        :meth:`new_variable`), registering each in ``name_to_var`` /
        ``var_to_name``.

        INPUT:

            - ``input_length`` -- int; the number of input variables
            - ``output_length`` -- int; the number of output variables
        """
        self.input_length = input_length
        self.output_length = output_length
        self.objective_terms = []
        self.name_to_var = {}
        self.var_to_name = {}
        # Enumerated indices of the input / output variables, filled by the
        # subclass when it allocates them.
        self.input_variables = []
        self.output_variables = []

    # ------------------------------------------------------------------ #
    #  Concrete helpers shared by all problem types                       #
    # ------------------------------------------------------------------ #

    def dump(self, path):
        r"""
        Serialize this problem to a JSON file.

        The model is serialized via :meth:`to_dict` so that :meth:`load` can
        reconstruct an equal object.

        INPUT:

            - ``path`` -- path of the JSON file to write

        .. SEEALSO::

            :meth:`to_dict`, :meth:`load`
        """
        with open(path, "w") as f:
            json.dump(self.to_dict(), f)

    @classmethod
    def load(cls, path):
        r"""
        Reconstruct a problem from a JSON file written by :meth:`dump`.

        INPUT:

            - ``path`` -- path of the JSON file to read

        OUTPUT:

            - an instance of ``cls`` equal to the dumped problem

        .. SEEALSO::

            :meth:`from_dict`, :meth:`dump`
        """
        with open(path) as f:
            data = json.load(f)
        return cls.from_dict(data)

    def to_dict(self):
        r"""
        Return a JSON-serializable representation of the model.

        The representation consists of the input/output lengths, the names of
        the model variables, and the constraints (each serialized to a string
        by :meth:`_constraint_to_string`). The input and output variables are
        implied by the lengths, and ``name_to_var`` / ``var_to_name`` are
        rebuilt by :meth:`from_dict` as the variables are re-allocated in
        enumeration order, so none of these are stored explicitly.

        .. NOTE::

            ``objective_terms`` is a generation-time helper and is *not* part
            of the serialized form: :meth:`to_dict` is meant to be called on a
            finished model, where the objective is already encoded in the
            constraints.

        OUTPUT:

            - dict; a representation from which :meth:`from_dict` reconstructs
              an equal problem

        .. SEEALSO::

            :meth:`from_dict`, :meth:`dump`
        """
        n_io = self.input_length + self.output_length
        return {
            "input_length": self.input_length,
            "output_length": self.output_length,
            "model_variables": [
                self.var_to_name[i]
                for i in range(n_io, len(self.var_to_name))
            ],
            "constraints": [
                self._constraint_to_string(constraint)
                for constraint in self.constraints()
            ],
        }

    @classmethod
    def from_dict(cls, data):
        r"""
        Reconstruct a problem from the output of :meth:`to_dict`.

        Instantiates the problem with the stored input/output lengths (which
        allocates the input and output variables), re-allocates the model
        variables via :meth:`new_variable`, then re-adds every constraint via
        :meth:`_add_constraint_from_string`.

        INPUT:

            - ``data`` -- dict; the output of :meth:`to_dict`

        OUTPUT:

            - an instance of ``cls`` corresponding to ``data``

        .. SEEALSO::

            :meth:`to_dict`, :meth:`load`
        """
        problem = cls(data["input_length"], data["output_length"])
        for name in data["model_variables"]:
            problem.new_variable(name)
        for constraint in data["constraints"]:
            problem._add_constraint_from_string(constraint)
        return problem

    def __eq__(self, other):
        r"""
        Compare two problems by their serialized content.

        Two problems are equal if they are of the same type and their
        :meth:`to_dict` representations coincide. This compares the models
        the problems represent, rather than object identity.
        """
        if type(self) is not type(other):
            return False
        return self.to_dict() == other.to_dict()

    def __hash__(self):
        r"""
        Hash a problem by its serialized content.

        Consistent with :meth:`__eq__`: equal problems (equal :meth:`to_dict`)
        hash equally.
        """
        return hash(json.dumps(self.to_dict(), sort_keys=True))

    def number_of_variables(self):
        r"""
        Return the number of variables in the model.

        OUTPUT:

            - int; the number of variables
        """
        return len(self.name_to_var)

    def number_of_constraints(self):
        r"""
        Return the number of constraints in the model.

        OUTPUT:

            - int; the number of constraints
        """
        return len(self.constraints())

    def append(self, sub_problem, inputs=None, prefix=""):
        r"""
        Merge ``sub_problem`` into this (master) problem and connect it.

        Every variable of ``sub_problem`` is copied into this problem under its
        ``prefix``-namespaced name, and every constraint of ``sub_problem`` is
        re-added here (serialized with the same ``prefix`` so it refers to the
        copies just created). Each variable in ``inputs`` is then tied to the
        copy of the corresponding input variable of ``sub_problem`` with an
        equality constraint, and ``sub_problem.objective_terms`` is merged into
        ``self.objective_terms``.

        This is the operation modeling code uses to assemble a master problem
        from the sub-models of a cipher's components/subciphers.

        .. NOTE::

            The same sub-model is often appended repeatedly (e.g. one S-box
            reused across a round), so its variable names collide. Pass a
            distinct ``prefix`` per call to namespace the copies and keep them
            unique in the master.

        INPUT:

            - ``sub_problem`` -- a :class:`PROBLEM_CVL` of the same type as
              ``self``; the sub-model to fold in
            - ``inputs`` -- optional ordered iterable of variables of this
              problem to tie to the input variables of ``sub_problem`` (matched
              by position). For the first sub-model these are the master's own
              input variables; for later ones they are the outputs returned by
              the previous :meth:`append`. When ``None``, no connection is
              added.
            - ``prefix`` -- str (default ``""``); prepended to every copied
              variable name to namespace this sub-model within the master

        OUTPUT:

            - the variables of this problem corresponding to the output
              variables of ``sub_problem`` (in order), so the caller can pass
              them as ``inputs`` when appending downstream sub-models.
        """
        copies = {
            index: self.new_variable(prefix + sub_problem.var_to_name[index])
            for index in range(sub_problem.number_of_variables())
        }
        for constraint in sub_problem.constraints():
            self._add_constraint_from_string(
                sub_problem._constraint_to_string(constraint, prefix=prefix)
            )
        if inputs is not None:
            for variable, sub_input in zip(inputs, sub_problem.input_variables):
                self.add_equality(variable, copies[sub_input])
        for factor, variable in sub_problem.objective_terms:
            self.objective_terms.append(
                (factor,
                 self.name_to_var[prefix + sub_problem.var_to_name[variable]])
            )
        return [copies[index] for index in sub_problem.output_variables]

    def new_variable(self, name=None):
        r"""
        Allocate a new model variable and register its name.

        The variable is enumerated with the next free index and recorded in
        ``name_to_var`` / ``var_to_name``. The actual variable in the
        underlying model is created by :meth:`_create_variable`.

        INPUT:

            - ``name`` -- str or ``None`` (default ``None``); the name to
              register the variable under. When ``None``, a default name is
              generated from the index. A :exc:`ValueError` is raised if a
              variable with this name already exists.

        OUTPUT:

            - a handle to the created variable, in the representation of the
              underlying model
        """
        index = len(self.name_to_var)
        if name is None:
            name = f"var{index}"
        if name in self.name_to_var:
            raise ValueError(f"a variable named {name!r} already exists")
        handle = self._create_variable()
        self.name_to_var[name] = index
        self.var_to_name[index] = name
        return handle

    # ------------------------------------------------------------------ #
    #  Interface to be implemented by the concrete problem types          #
    # ------------------------------------------------------------------ #

    @abstractmethod
    def _create_variable(self):
        r"""
        Create a new variable in the underlying model and return a handle.

        Called by :meth:`new_variable` once per variable, in enumeration order.
        The backend allocates the variable with its own native mechanism and
        keeps track of its own count; it does not receive the enumeration
        index.

        OUTPUT:

            - a handle to the created variable
        """

    @abstractmethod
    def add_equality(self, variable_a, variable_b):
        r"""
        Add a constraint forcing two variables to be equal.

        Used by :meth:`append` to connect a provided variable to the copy of a
        sub-model's input variable.

        INPUT:

            - ``variable_a``, ``variable_b`` -- two variables of this problem
              (in the representation returned by :meth:`new_variable`) that
              shall be forced equal
        """

    @abstractmethod
    def constraints(self):
        r"""
        Return the constraints currently in the model.

        Used by :meth:`to_dict`, :meth:`number_of_constraints` and
        :meth:`append`. The returned objects are the native constraints of the
        underlying model; they are only ever passed back to
        :meth:`_constraint_to_string`.

        OUTPUT:

            - a list of the model's native constraints
        """

    @abstractmethod
    def _constraint_to_string(self, constraint, prefix=""):
        r"""
        Serialize a single native constraint to a string.

        Each variable the constraint refers to is written by its name; when
        ``prefix`` is given it is prepended to those names. Together with
        :meth:`_add_constraint_from_string` this is the only backend-specific
        part of serialization; the rest of :meth:`to_dict` / :meth:`from_dict`
        is handled generically. :meth:`append` uses ``prefix`` to namespace a
        sub-model's variables when merging it into a master.

        INPUT:

            - ``constraint`` -- one native constraint, as returned by
              :meth:`constraints`
            - ``prefix`` -- str (default ``""``); prepended to each variable
              name written to the string

        OUTPUT:

            - str; a representation consumed by :meth:`_add_constraint_from_string`
        """

    @abstractmethod
    def _add_constraint_from_string(self, string):
        r"""
        Parse a constraint string and add the constraint to the model.

        The inverse of :meth:`_constraint_to_string`. Called by
        :meth:`from_dict` once all variables have been re-allocated, so the
        variables the constraint refers to already exist.

        INPUT:

            - ``string`` -- str; a constraint as produced by
              :meth:`_constraint_to_string`
        """

    @abstractmethod
    def finish(self, model_options, first_iter=False):
        r"""
        Finalize the model so it is ready to be solved.

        Adds the "input is active" constraint and the constraints encoding the
        objective / weight built from ``objective_terms``, writes the companion
        files, and, if requested by ``model_options``, serializes the model.

        INPUT:

            - ``model_options`` -- see
              :class:`civerly.model_options.MODEL_OPTIONS`
            - ``first_iter`` -- bool (default ``False``); whether this is the
              first modeling iteration (only then are the activeness constraint
              and the objective/weight bound added)
        """

    @abstractmethod
    def write(self, path=None):
        r"""
        Write the model to a file in the problem type's native format.

        INPUT:

            - ``path`` -- optional path to write to; subclasses may derive a
              default from ``model_options`` when ``None``
        """

    @abstractmethod
    def solve(self, model_options, **kwargs):
        r"""
        Solve this problem using the solver selected in ``model_options``.

        INPUT:

            - ``model_options`` -- see
              :class:`civerly.model_options.MODEL_OPTIONS`
            - ``**kwargs`` -- forwarded solve parameters (e.g. ``time_limit``,
              ``number_of_solutions``)

        OUTPUT:

            - a result ``dict`` (or list of such dicts when several solutions
              are requested) in the shape returned by the solver's ``solve`` /
              ``solve_multiple`` methods.
        """

    @abstractmethod
    def exclude_solution(self, results):
        r"""
        Add a constraint forbidding the given solution.

        Used to enumerate several distinct solutions: after a solution is
        found, this makes sure the exact same assignment cannot be returned
        again on a subsequent solve.

        INPUT:

            - ``results`` -- dict; a solution (as returned by the solver) to be
              excluded
        """
