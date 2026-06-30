from sage.numerical.mip import MixedIntegerLinearProgram

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


    def dump(self):
        """
        Implement JSON serialization.
        """
        return {
            "maximization": self.backend.is_maximization(),
            "variables": [
                # TODO. Should be something like this:
                #   var.name for var in range(self.number_of_variables())
            ],
            "objective": [
                self.backend.objective_coefficient(i)
                for i in range(self.number_of_constraints())
            ],
            "constraints": [
                self.backend.row(i)
                for i in range(self.number_of_constraints())
            ],
        }
    
