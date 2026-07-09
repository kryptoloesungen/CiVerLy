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
        # always default to glpk solver for sage wrapper to minimize dependencies
        kwargs.pop("solver", None)
        super().__init__(*args, solver="GLPK", **kwargs)
        self.backend  = self.get_backend()
        self.__vars = {}

        self.MILP_IN  = self.new_variable(name="IN",  binary=True)
        self.MILP_OUT = self.new_variable(name="OUT", binary=True)
        self.X = None

    def __eq__(self, other):
        """
        Compares two MILP_CVL instances with each other by considering
        the corresponding dictionaries (see :meth:``to_dict``).

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
        return self.__vars

    def new_variable(self, *args, **kwargs):
        """
        Override :meth:``MixedIntegerLinearProgram.new_variable`` to 
        also store this variable as an attribute of ``self``.
        """
        name = kwargs.get("name")
        var = super().new_variable(*args, **kwargs)
        self.__vars[name] = var
        return var

    def dump(self, filename):
        with open(filename, "w") as f:
            json.dump(self.to_dict(), fp=f)
        return

    def to_dict(self):
        """
        Make ``MILP_CVL`` json-serializable by creating a dictionary with 
        all the relevant information.
        """
        return {
            "maximization": self.backend.is_maximization(),
            "variables": [ # has the form [('x', 0, 0), ('x', 1, 1), ...]
                (index, int(k), int(str(v)[2:]))
                for index, var in list(self.vars.items())
                for k, v in var.items()
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
        """
        with open(filename) as f:
            data = json.load(f)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data):
        """
        Reconstruct a MILP_CVL from the output of :meth:``to_dict``.
        """
        milp = cls(maximization=data["maximization"])

        # Map variable ids back to sage variables.
        groups = {}
        id_to_var = {}

        # sort for var_id (the backend index), so that milp.new_variable
        # implicitly reconstructs them
        for group, key, var_id in sorted(data["variables"], key=lambda x: x[2]):
            if group not in groups:
                groups[group] = milp.new_variable(name=group)

            sage_var = groups[group][key]
            id_to_var[var_id] = sage_var

        # rebuild objective
        obj = 0
        for var_id, coef in enumerate(data["objective"]):
            obj += coef * id_to_var[var_id]

        milp.set_objective(obj)

        # Reconstruct the constraints.
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