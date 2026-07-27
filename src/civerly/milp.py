from sage.numerical.mip import MixedIntegerLinearProgram
import json

class MILP_CVL(MixedIntegerLinearProgram):
    r"""
    Wrapper for SageMath's :class:``MixedIntegerLinearProgram``, supporting JSON
    serialization.

    EXAMPLE:

    ``MILP_CVL`` can be instantiated exactly like ``MixedIntegerLinearProgram``.

        sage: from civerly.milp import MILP_CVL
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

        - New attributes, to make them easier to access:
            - ``vars`` -- dict[str -> MIPVariable]; Stores all MIPVariables created by :meth:``self.new_variable``.

            - ``VAR_IN``, ``VAR_OUT`` -- MIPVariable; The input and output variables.

            - ``VAR_MODEL`` -- list[MIPVariable]; The standard variable to be used for modeling.
        """
        # always default to glpk solver for sage wrapper to minimize dependencies
        kwargs.pop("solver", None)
        super().__init__(*args, solver="GLPK", **kwargs)
        self.backend  = self.get_backend()
        self.__vars = {}

        self.VAR_IN  = self.new_variable(name="IN",  binary=True)
        self.VAR_OUT = self.new_variable(name="OUT", binary=True)
        self.VAR_MODEL = None

    def __eq__(self, other):
        """
        Compares two MILP_CVL instances with each other by considering
        the corresponding dictionaries (see :meth:``to_dict``).
        Comparing two :class:``MixedIntegerLinearProgram`` objects considers the 
        objects themselves, not whether the MILPs they represent are actually equal,
        which is done here.

        TESTS:
        
            sage: import tempfile
            sage: from civerly.milp import MILP_CVL
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

            sage: from civerly.milp import MILP_CVL
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
        """
        if not isinstance(other, MILP_CVL):
            return False
        return self.to_dict() == other.to_dict()

    @property
    def vars(self):
        """
        A dictionary containing all the variables added via :meth:``new_variable``.
        """
        return self.__vars

    def get_var(self, index):
        for var in self.vars.values():
            for i, b_var in var.items():
                if var.get_index(i) == index:
                    return b_var
        raise AssertionError("var not found")


    def new_variable(self, *args, **kwargs):
        """
        Override :meth:``MixedIntegerLinearProgram.new_variable`` to 
        also store this variable inside ``self.vars``, and store the 
        MIPVariable type as its attribute, so that we can recover it
        when reconstructing it inside `from_dict`.
        
        There are four variable types:
        real (default), binary, integer, nonnegative.
        Setting them appropriately is crucial, as it would otherwise
        change the underlying MILP and its solution space completely.
        """
        name = kwargs.get("name", None)
        var_types = [
            kwargs.get("real", None),
            kwargs.get("binary", None),
            kwargs.get("integer", None),
            kwargs.get("nonnegative", None),
        ]
        if any(var_types): 
            var_type = var_types.index(True)
        else:
            var_type = 0 # 'real' is the default

        var = super().new_variable(*args, **kwargs)
        # add new attributes + methods
        var.type = var_type
        var.get_index = lambda i: list(var[i].dict().keys())[0]

        self.__vars[name] = var
        return var

    def dump(self, filename):
        """
        Serialize ``self`` into a dictionary using :meth:`to_dict`,
        and write to ``filename`` afterwards. Takes the parameter:

        - filename -- str; The json filename to dump ``self`` into.
        """
        with open(filename, "w") as f:
            json.dump(self.to_dict(), fp=f)
        return

    def to_dict(self):
        """
        Make ``MILP_CVL`` json-serializable by creating a dictionary with 
        the following information:

        - maximization -- bool; Determines if the objective is to maximize or not.

        - variables -- list of the form ``[(name, index, backend_index)]``, where:
            - ``name`` -- string; The name of the MIPVariable object.
            - ``index`` -- int; The index of this variable inside the MIPVariable object
              (recall, MIPVariables are dictionaries)
            - ``backend_index`` -- int; The index of the corresponding backend variable. 
              In the backend, the variables are of the form ``x_1234``, ``backend_index``
              stores the integer 1234.
            - ``var_type`` -- int; an integer indicating whether the MIPVariable is real (0),
              binary (1), integer (2), nonnegative (3).

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
            - variables[616] - variables[617] - variables[619] \leq 0``
            
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
            [[(0, 1), (-1.0, 1.0), [0.0, 0.0]],
             [(2, 3), (-1.0, 1.0), [0.0, 0.0]],
             [(4, 5), (-1.0, 1.0), [0.0, 0.0]],
             [(6, 7), (-1.0, 1.0), [0.0, 0.0]],
             [(8, 9), (-1.0, 1.0), [0.0, 0.0]],
             ...
        """
        return {
            "maximization": self.backend.is_maximization(),
            "variables": [ # has the form [('x', 0, 0, <var_type>), ('x', 1, 1, <var_type>), ...]
                (name, int(index), int(str(backend_index)[2:]), var.type)
                for name, var in list(self.vars.items())
                for index, backend_index in var.items()
            ],
            "objective": [
                float(self.backend.objective_coefficient(i))
                for i in range(self.number_of_variables())
            ],
            "constraints": [
                list(zip(*sorted(zip( # sort them with same permutation
                    list(map(int, self.backend.row(i)[0])),   # indices
                    list(map(float, self.backend.row(i)[1])), # coeffs
                )))) + [[
                    float(e)
                    if e is not None else None
                    for e in self.backend.row_bounds(i)
                ]]
                for i in range(self.number_of_constraints())
            ],
        }
    
    @classmethod
    def load(cls, filename):
        """
        Load the MILP_CVL object from a json file, using :meth:``from_dict``.

        TESTS::

        Dumping the MILP from a previous analysis, loading it and solving it
        shall result in the exact same solution (when solving process
        is deterministic):

            sage: from civerly.milp import MILP_CVL
            sage: from civerly.cipher_implementations.gift import GIFT_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: gift = GIFT_CVL(R=3)
            sage: # optional - scip, espresso
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
            3648 variables and 6081 constraints were written to...
            7
            sage: gift.milp.dump(model_options.path / "milp.json")
            sage: from civerly.milp import MILP_CVL
            sage: from civerly.solvers import SCIP_CVL
            sage: milp = MILP_CVL.load(model_options.path / "milp.json")
            sage: milp.write_mps(str(model_options.path / "milp.mps"))
            Writing problem data to ...
            21658 records were written
            sage: # optional - scip
            sage: scip = SCIP_CVL()
            sage: result = scip.solve(model_options.path / "milp.mps")
            sage: result['assignment'] == gift.result['assignment']
            True
            sage: import shutil
            sage: shutil.rmtree(model_options.path, ignore_errors=True)
        """
        with open(filename) as f:
            data = json.load(f)
        return cls.from_dict(data)

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
            sage: from civerly.milp import MILP_CVL
            sage: milp = MILP_CVL.from_dict(data)
            sage: milp == cipher.milp
            True
        """
        milp = cls(maximization=data["maximization"])
        milp.VAR_MODEL = []

        # map variable ids back to sage variables
        mip_vars = {}
        id_to_var = {}

        # sort for var_id (the backend index), so that milp.new_variable
        # implicitly reconstructs them
        for var_name, key, var_id, var_type in sorted(data["variables"], key=lambda x: x[2]):
            if var_name not in mip_vars:
                type_attr = ["real", "binary", "integer", "nonnegative"][var_type]
                kwargs = {"name": var_name, type_attr: True}
                mip_vars[var_name] = milp.new_variable(**kwargs)
                if var_name == "IN":
                    milp.VAR_IN = mip_vars[var_name]
                elif var_name == "OUT":
                    milp.VAR_OUT = mip_vars[var_name]
                else:
                    milp.VAR_MODEL.append(mip_vars[var_name])

            sage_var = mip_vars[var_name][key]
            id_to_var[var_id] = sage_var

        # rebuild objective
        obj = 0
        for var_id, coef in enumerate(data["objective"]):
            obj += coef * id_to_var[var_id]

        milp.set_objective(obj)

        # reconstruct the constraints
        for indices, coefficients, (lower, upper) in data["constraints"]:

            expr = sum(
                coef * id_to_var[var_id]
                for var_id, coef in zip(indices, coefficients)
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