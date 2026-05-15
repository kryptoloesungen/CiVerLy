r"""
Component class of CiVerLy.

``Component`` implements the fundamental components of a ``Cipher``, ranging
from the linear layer (``LinearLayer_CVL``) over to SBoxes (``SBox_CVL``) and
modular additions (``ModAdd_CVL``). Calling the ``Component`` performs the
corresponding evaluation (e.g. calling ``SBox_CVL`` performs a table lookup of
the SBox with which the component is initialized).
"""
import os
import json
import zlib
from math import log2, gcd, ceil
from abc import ABC, abstractmethod
from collections.abc import Iterable

from sage.crypto.sbox import SBox
from sage.modules.free_module_element import vector
from sage.modules.vector_mod2_dense import Vector_mod2_dense
from sage.rings.integer_ring import ZZ
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.combinat.permutation import Permutation
from sage.matrix.constructor import Matrix as matrix
from sage.structure.element import Matrix as matrix_type
from sage.matrix.special import identity_matrix, block_matrix
from sage.sat.solvers.dimacs import DIMACS
from sage.numerical.mip import MixedIntegerLinearProgram
from sage.geometry.polyhedron.constructor import Polyhedron

from civerly.util import list_of_predecessor_vector_indices
from civerly.util import hw, hw_tau, suppress_output
from civerly.util import reduction_algorithm_ST17
from civerly.util import vec_to_int, int_to_vec
from civerly.util import _write_espresso_input
from civerly.util import _read_espresso_output
from civerly.util import translate_sat_clause
from civerly.model_options import GRANULARITY, LINEAR_LAYER_MODELING
from civerly.model_options import CRYPTANALYSIS, OPTIMIZATION
from civerly.model_options import InvalidModelOptionException
from civerly.model_options import SBOX_MODELING
from civerly.distorted_balls import distorted_balls
from civerly.solvers import ESPRESSO_CVL, NO_MILP_SOLVER_CVL, NO_LOGIC_MINIMIZER_CVL


class Component(ABC):
    r"""
    Implement the basic structure of all components.

    .. WARNING::
        This component can and **should not be instantiated**. It is rather a
        superclass of each of the proper components such as SBoxes, XOR, etc.

    EXAMPLES::

        sage: from civerly.component import Component
        sage: comp = Component(16, 16)
        Traceback (most recent call last):
        ...
        TypeError: Can't instantiate abstract class Component...

    .. admonition:: For future development

        The ``Component`` class dictates what methods any subclass should
        implement. In order for a class to be a functional ``Component``
        subclass, it needs implement the following (besides inheriting from
        ``Component``):

            - ``__init__()`` -- The init function must specify (implicitly or
              by taking parameters) the in- and output length of the component.
            - ``eval()`` -- Any Component should be possible to evaluate, in
              order to test the correctness of the implementation with test
              vectors. ``eval()`` should accept a bit array as input and should
              return a bit array on the output as well.
            - ``__repr__()`` -- Not necessary to implement, but convenient.
              When printing the component, a meaningful string should be
              returned, such as "LL(16 -> 32)" for a linear layer going from a
              16-bit input to a 32-bit output.
            - ``_model_milp()`` -- Each component must specify how to be
              modeled with MILP (if at all).
            - ``_model_sat()`` -- Each component must specify how to be modeled
              with SAT (if at all).
    """

    def __init__(self, input_length, output_length, name=None):
        r"""
        Initialize abstract ``Component`` class.

        INPUT:
            - ``input_length`` -- integer; Represents the number of bits going
              into the component
            - ``output_length`` -- integer; Represents the number of bits going
              out of the component
            - ``name`` -- string; The component name for easier identification
              (optional)
        """
        if name is not None:
            self.__name = name
        else:
            self.__name = "Unnamed Component"
        self.__input_length = input_length
        self.__output_length = output_length
        self._return_immediately_ = False
        self.results = []

    def __call__(self, x):
        r"""Evaluate this component."""
        return self.eval(x)

    @property
    def input_length(self):
        r"""The length of the input in bits."""
        return self.__input_length

    @property
    def output_length(self):
        r"""The length of the output in bits."""
        return self.__output_length

    @property
    def name(self):
        r"""The name used to describe this component."""
        return self.__name

    @abstractmethod
    def eval(self, x):
        r"""Evaluate this component."""
        pass

    def __repr__(self):
        r"""Describe this component."""
        return self.name

    def model(self, model_options):
        r"""Model this component.

        This method merely relays ``model_options`` to an appropiate
        subroutine.
        """
        if model_options.optimization == OPTIMIZATION.MILP:
            return self._model_milp(model_options)
        elif model_options.optimization == OPTIMIZATION.SAT:
            return self._model_sat(model_options)
        else:
            raise InvalidModelOptionException(
                model_options.optimization, OPTIMIZATION
                )

    def _init_model(self, model_options):
        r"""Initialize empty MILP or SAT model for this component."""
        if model_options.optimization == OPTIMIZATION.MILP:
            self.sum_arr_milp = []
            self.milp = MixedIntegerLinearProgram(
                maximization=False, solver="GLPK"
            )
            self.MILP_IN = self.milp.new_variable(name="IN", binary=True)
            self.MILP_OUT = self.milp.new_variable(name="OUT", binary=True)
        elif model_options.optimization == OPTIMIZATION.SAT:
            self.sum_arr_sat = []
            if model_options.granularity == GRANULARITY.WORDWISE:
                raise InvalidModelOptionException(
                    model_options.granularity,
                    message="Wordwise modeling is not supported using SAT"
                )
            if model_options.path is not None:
                fn = model_options.path/f"{self.name.replace(' ', '_')}.cnf"
                self.sat = DIMACS(filename=fn)
            else:
                self.sat = DIMACS()
            self.SAT_IN = [self.sat.var() for _ in range(self.input_length)]
            self.SAT_OUT = [self.sat.var() for _ in range(self.output_length)]
        else:
            raise InvalidModelOptionException(
                model_options.optimization, OPTIMIZATION
            )

    def _copy_over_dictionaries_recursively(self, prev, model_options):
        return

    def _to_tikz(self, _comps=[]):
        r"""Generate TikZ code for this component."""
        return ""

    def __eq__(self, other):
        r"""Check if ``self`` and ``other`` are the same."""
        if type(self) is type(other):
            return hash(self) == hash(other)
        return False

    def __lt__(self, other):
        r"""
        Compare ``self`` and ``other`` by their name,
        if both are components.
        """
        if isinstance(other, Component):
            return self.name < other.name
        return True

    def __gt__(self, other):
        r"""
        Compare ``self`` and ``other`` by their name,
        if both are components.
        """
        if isinstance(other, Component):
            return self.name > other.name
        return False

    def __hash__(self):
        r"""Compute the hash of this component."""
        liste = []
        for key, value in self.__dict__.items():
            if isinstance(value, (bool, str)):
                continue
            elif isinstance(value, (MixedIntegerLinearProgram, DIMACS)):
                continue
            elif any([word in key for word in [
                "wordsize", "milp", "sat", "MILP", "SAT"
            ]]):
                continue
            elif isinstance(value, matrix_type):
                liste.append((key, tuple([tuple(v) for v in value])))
            elif isinstance(value, (Iterable, Vector_mod2_dense)):
                liste.append((key, tuple(value)))
            else:
                liste.append((key, value))
        return hash(tuple(liste))


class I_CVL(Component):
    r"""
    The identity component. It maps any input vector :math:`x` to :math:`x`
    itself, given that :math:`x` has the correct size (``input_length``).
    """

    def __init__(self, input_length, name=None):
        r"""
        Initialize the identity component.

        INPUT:

            - ``input_length`` -- integer; The block size of the identity component.
              Since ``input_length == output_length`` in this case, it is not necessary to
              pass the output_length as a seperate parameter.
            - ``name`` -- string; The component name for easier identification (optional)

        OUTPUT: An instantiated ``I_CVL`` object.

        EXAMPLES::

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.component import I_CVL
            sage: identity = I_CVL(16)
            sage: hex(vec_to_int(identity(int_to_vec(0x1f2,16))))
            '0x1f2'
            sage: int_to_vec(0x1929ab6, 16)
            Traceback (most recent call last):
            ...
            ValueError: Input size of 26385078 too large (can at most be 65536)

        TESTS::

            sage: from civerly.component import I_CVL
            sage: from civerly.model_options import *
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.MILP,
            ....:   granularity=GRANULARITY.BITWISE)
            sage: I_CVL(4).model(model_options)
            Boolean Program (no objective, 8 variables, 4 constraints)
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE)
            sage: model = I_CVL(4).model(model_options)
            sage: (model.nvars(), len(model.clauses()))
            (8, 8)
        """
        super().__init__(input_length, input_length, name=name)

    def eval(self, x):
        r"""Evaluate the output ``I_CVL(x) = x``."""
        assert len(x) == self.input_length, (
            f"Wrong input size {len(x)}, must be {self.input_length}"
        )
        return x

    def __repr__(self):
        r"""Describe this component."""
        if self.name is not None:
            return self.name
        return f"Identity({self.input_length})"

    def _to_dict(self):
        return {
            "type": "I_CVL",
            "name": self.name,
            "input_length": int(self.input_length),
        }

    @classmethod
    def _from_dict(cls, d):
        return cls(d["input_length"], name=d.get("name"))

    def _model_milp(self, model_options):
        r"""
        Model this component in MILP.

        ``I_CVL`` is trivial to model, the input should be equal to the output.
        """
        self._init_model(model_options)
        if model_options.granularity == GRANULARITY.WORDWISE:
            divide_by = self.wordsize
        elif model_options.granularity == GRANULARITY.BITWISE:
            divide_by = 1
        else:
            raise InvalidModelOptionException(
                model_options.granularity, GRANULARITY
            )

        for i in range(self.input_length // divide_by):
            self.milp.add_constraint(self.MILP_OUT[i] == self.MILP_IN[i])
        return self.milp

    def _model_sat(self, model_options):
        r"""
        Model this component in SAT.

        ``I_CVL`` is trivial to model, the input should be equal to the output.
        """
        self._init_model(model_options)
        if model_options.granularity == GRANULARITY.BITWISE:
            for i in range(self.input_length):
                # SATizing equalities:
                #   (x == y) <=> (x \lor -y) \land (-x \lor y)
                self.sat.add_clause((self.SAT_OUT[i], -self.SAT_IN[i]))
                self.sat.add_clause((-self.SAT_OUT[i], self.SAT_IN[i]))
            return self.sat
        else:
            raise InvalidModelOptionException(
                model_options.granularity, GRANULARITY
            )


class C_CVL(Component):
    r"""
    .. NOTE::
        In most of the cases, it might be easier to use ``ConstXOR_CVL``
        instead of this.

    The constant component. Used e.g. for implementing round constant addition
    in ciphers. This is a special component, as it doesn't need an input and
    generates output itself. Furthermore, evaluating this component ignores
    the input and outputs just the set constant.

    INPUT:

        - ``output_length`` -- integer; The block size of the component.
          ``input_length`` is not a parameter since this component does not
          need inputs in the Cipher graph.
        - ``const`` -- integer; The constant which the component should output
          upon evaluation.
        - ``name`` -- string; The component name for easier identification
          (optional).

    OUTPUT: A constant component initialized with ``const``.
    """
    def __init__(self, output_length, const, name=None):
        super().__init__(0, output_length, name=name)
        self.__const = const

    @property
    def const(self):
        return self.__const

    def eval(self, x=None):
        return int_to_vec(self.const, self.output_length)

    def __repr__(self):
        if self.name is not None:
            return self.name
        return f"Constant({self.output_length})"

    def _to_dict(self):
        return {
            "type": "C_CVL",
            "name": self.name,
            "output_length": int(self.output_length),
            "const": int(self.const),
        }

    @classmethod
    def _from_dict(cls, d):
        return cls(d["output_length"], d["const"], name=d.get("name"))

    def _model_milp(self, model_options):
        self._init_model(model_options)
        # wordsize is set externally in wordbasedcipher.add_subcipher
        if model_options.granularity == GRANULARITY.WORDWISE:
            divide_by = self.wordsize
        elif model_options.granularity == GRANULARITY.BITWISE:
            divide_by = 1
        else:
            raise InvalidModelOptionException(
                model_options.granularity, GRANULARITY
            )

        if model_options.cryptanalysis == CRYPTANALYSIS.DIFFERENTIAL:
            for i in range(self.output_length // divide_by):
                self.milp.add_constraint(self.MILP_OUT[i] == 0)
            return self.milp
        elif model_options.cryptanalysis == CRYPTANALYSIS.LINEAR:
            # For linear modeling, C_CVL is "don't care"
            # Therefore, return empty milp
            return self.milp

    def _model_sat(self, model_options):
        self._init_model(model_options)
        if model_options.granularity == GRANULARITY.BITWISE:
            if model_options.cryptanalysis == CRYPTANALYSIS.DIFFERENTIAL:
                for i in range(self.output_length):
                    self.sat.add_clause((-self.SAT_OUT[i], ))
                return self.sat
            elif model_options.cryptanalysis == CRYPTANALYSIS.LINEAR:
                # For linear modeling, C_CVL is "don't care"
                for i in range(self.output_length):
                    self.sat.add_clause((self.SAT_OUT[i], -self.SAT_OUT[i]))
                return self.sat
        else:
            raise InvalidModelOptionException(
                model_options.granularity, GRANULARITY
            )


class RK_CVL(C_CVL):
    r"""
    .. NOTE::
        In most of the cases, it might be easier to use ``RoundkeyXOR_CVL``
        instead of this.

    The round-key component. Acts very similarily to ``C_CVL``, with the
    difference that the ``const`` value is allowed to be changed after
    instantiation. This allows for using test vectors with non-zero round keys,
    while treating the key schedules functionality as a blackbox.

    INPUT:

        - ``output_length`` -- integer; The block size of the
          component. ``input_length`` is not a parameter since this component
          does not need inputs in the Cipher graph.
        - ``const`` -- integer; The constant which the component should output
          upon evaluation.
        - ``name`` -- string; The component name for easier identification
          (optional).

    OUTPUT: A round-key component initialized with ``const``.
    """
    def __init__(self, output_length, const, name=None):
        super().__init__(output_length, const, name=name)

    @property
    def const(self):
        return super().const

    @const.setter
    def const(self, value):
        # Setter in order to be able to change the RK value
        self._C_CVL__const = value

    def eval(self, x=None):
        return int_to_vec(self.const, self.output_length)

    def __repr__(self):
        if self.name is not None:
            return self.name
        return f"Roundkey({self.output_length})"

    def _to_dict(self):
        return {
            "type": "RK_CVL",
            "name": self.name,
            "output_length": int(self.output_length),
            "const": int(self.const),
        }

    @classmethod
    def _from_dict(cls, d):
        return cls(d["output_length"], d["const"], name=d.get("name"))


class ConstXOR_CVL(Component):
    r"""
    The ``ConstXOR_CVL`` component. Used for an easier implementation of round
    constant addition in ciphers instead of using ``C_CVL`` and ``XOR_CVL``
    seperately.

    INPUT:

        - ``output_length`` -- integer; The block size of the component.
        - ``const`` -- integer; The constant which the component should output
          upon evaluation.
        - ``name`` -- string; The component name for easier identification
          (optional).

    OUTPUT: A ``ConstXOR_CVL`` component initialized with ``const``, which is
    immutable.

    EXAMPLES::

        sage: from civerly.util import int_to_vec, vec_to_int
        sage: from civerly.component import ConstXOR_CVL
        sage: constxor = ConstXOR_CVL(32, 0x11112222)
        sage: hex(vec_to_int(constxor(int_to_vec(0xababcdcd,32))))
        '0xbabaefef'
        sage: constxor.const = 0x1019b214
        Traceback (most recent call last):
        ...
        AttributeError: ...

    TESTS::

        sage: from civerly.model_options import *
        sage: from civerly.solvers import *
        sage: from civerly.component import ConstXOR_CVL
        sage: constxor = ConstXOR_CVL(32, 0x11112222)
        sage: model_options = MODEL_OPTIONS(
        ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:   optimization=OPTIMIZATION.MILP,
        ....:   granularity=GRANULARITY.BITWISE)
        sage: constxor.model(model_options)
        Boolean Program (no objective, 64 variables, 32 constraints)
        sage: model_options = MODEL_OPTIONS(
        ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:   optimization=OPTIMIZATION.SAT,
        ....:   granularity=GRANULARITY.BITWISE)
        sage: model = constxor.model(model_options)
        sage: (model.nvars(), len(model.clauses()))
        (64, 64)


    """
    def __init__(self, output_length, const, name=None):
        super().__init__(output_length, output_length, name=name)
        self.__const = const

    @property
    def const(self):
        return self.__const

    def eval(self, x):
        return x + int_to_vec(self.const, self.output_length)

    def __repr__(self):
        if self.name is not None:
            return self.name
        return f"ConstantXOR({self.output_length})"

    def _to_dict(self):
        return {
            "type": "ConstXOR_CVL",
            "name": self.name,
            "output_length": int(self.output_length),
            "const": int(self.const),
        }

    @classmethod
    def _from_dict(cls, d):
        return cls(d["output_length"], d["const"], name=d.get("name"))

    def _model_milp(self, model_options):
        self._init_model(model_options)
        # wordsize is set externally in wordbasedcipher.add_subcipher
        if model_options.granularity == GRANULARITY.WORDWISE:
            divide_by = self.wordsize
        elif model_options.granularity == GRANULARITY.BITWISE:
            divide_by = 1

        for i in range(self.input_length // divide_by):
            self.milp.add_constraint(self.MILP_OUT[i] == self.MILP_IN[i])
        return self.milp

    def _model_sat(self, model_options):
        self._init_model(model_options)
        if model_options.granularity == GRANULARITY.BITWISE:
            for i in range(self.input_length):
                self.sat.add_clause((self.SAT_OUT[i], -self.SAT_IN[i]))
                self.sat.add_clause((-self.SAT_OUT[i], self.SAT_IN[i]))
            return self.sat
        else:
            raise InvalidModelOptionException(
                model_options.granularity, GRANULARITY
            )


class RoundkeyXOR_CVL(ConstXOR_CVL):
    r"""
    The ``RoundkeyXOR_CVL`` component. Used for an easier implementation of
    round constant addition in ciphers instead of using ``C_CVL`` and
    ``XOR_CVL`` seperately. Acts very similarily to the ``ConstXOR_CVL``
    component, with the difference that the ``const`` value is allowed to be
    changed after instantiation. This allows for using test vectors with
    non-zero round keys, while treating the key schedules functionality as a
    blackbox.

    INPUT:

        - ``output_length`` -- integer; The block size of the component.

        - ``const`` -- integer; The constant which the component should output
          upon evaluation.

        - ``name`` -- string; The component name for easier identification
          (optional)

    OUTPUT: A ``RoundkeyXOR_CVL`` component initialized with ``const``.

    EXAMPLES::

        sage: from civerly.util import int_to_vec, vec_to_int
        sage: from civerly.component import RoundkeyXOR_CVL
        sage: roundkeyxor = RoundkeyXOR_CVL(32, 0x11112222)
        sage: hex(vec_to_int(roundkeyxor(int_to_vec(0xababcdcd,32))))
        '0xbabaefef'
        sage: roundkeyxor.const = 0x1019b214
        sage: hex(vec_to_int(roundkeyxor(int_to_vec(0xababcdcd,32))))
        '0xbbb27fd9'
    """
    def __init__(self, output_length, const, name=None):
        r"""

        """
        super().__init__(output_length, const, name=name)

    @property
    def const(self):
        return super().const

    @const.setter
    def const(self, value):
        r"""
        Setter in order to be able to change the RK value
        """
        self._ConstXOR_CVL__const = value

    def eval(self, x):
        return super().eval(x)

    def __repr__(self):
        if self.name is not None:
            return self.name
        return f"RoundkeyXOR({self.output_length})"

    def _to_dict(self):
        return {
            "type": "RoundkeyXOR_CVL",
            "name": self.name,
            "output_length": int(self.output_length),
            "const": int(self.const),
        }

    @classmethod
    def _from_dict(cls, d):
        return cls(d["output_length"], d["const"], name=d.get("name"))


class XOR_CVL(Component):
    r"""
    The ``XOR_CVL`` component. Accepts the vector :math:`x||y` and returns
    :math:`x \oplus y`.

    INPUT:

        - ``word_length`` -- integer; Determines the word length. The
          evaluation map will map an input of size :math:`2 \cdot`
          ``word_length`` to an output of length ``word_length``.
        - ``name`` -- string; The component name for easier identification
          (optional)

    OUTPUT: An ``XOR_CVL`` instance of length ``word_length``.

    EXAMPLES::

        sage: from civerly.util import int_to_vec, vec_to_int
        sage: from civerly.component import XOR_CVL
        sage: xor_component = XOR_CVL(32)
        sage: hex(vec_to_int(xor_component(int_to_vec(
        ....:   0x11111111_12121212, 64
        ....: ))))
        '0x3030303'
    """
    def __init__(self, word_length, name=None):
        super().__init__(2*word_length, word_length, name=name)
        self.__word_length = word_length

    def eval(self, x):
        # Accept a vector of length 2n ``x||y``, and return ``x \oplus y``.
        A = vec_to_int(x[:self.word_length])
        B = vec_to_int(x[self.word_length:])
        return int_to_vec(A ^ B, self.word_length)

    @property
    def word_length(self):
        return self.__word_length

    def __repr__(self):
        if self.name is not None:
            return self.name
        return f"XOR({(self.word_length)})"

    def _to_dict(self):
        return {
            "type": "XOR_CVL",
            "name": self.name,
            "word_length": int(self.word_length),
        }

    @classmethod
    def _from_dict(cls, d):
        return cls(d["word_length"], name=d.get("name"))

    def _model_milp(self, model_options):
        """
        Models the XOR of two words by creating a MILP/SAT model of the
        feasibility region for the differential/linear transitions.

        INPUT:

            - ``model_options`` -- civerly.model_options.MODEL_OPTIONS Option
            specifying the model to generate (e.g. using MILP or SAT, linear
            or differential cryptanaylsis, bit-wise or word-wise modeling)

        OUTPUT: A MILP/SAT model
        """
        self._init_model(model_options)
        if model_options.cryptanalysis == CRYPTANALYSIS.DIFFERENTIAL:
            # Differences of the two inputs a, b and the output c need to
            # sum to zero. This is modeled as
            # -a + b + c >= 0
            #  a - b + c >= 0
            #  a + b - c >= 0
            # -a - b - c >= -2 (only for bitwise granularity)
            # where the last constraint excludes the case 1 = a = b = c
            # in the bitwise setting
            if model_options.granularity == GRANULARITY.BITWISE:
                for i in range(self.word_length):
                    self.milp.add_constraint(-self.MILP_IN[i]+self.MILP_IN[i+self.word_length]+self.MILP_OUT[i] >= 0)
                    self.milp.add_constraint(self.MILP_IN[i]-self.MILP_IN[i+self.word_length]+self.MILP_OUT[i] >= 0)
                    self.milp.add_constraint(self.MILP_IN[i]+self.MILP_IN[i+self.word_length]-self.MILP_OUT[i] >= 0)
                    self.milp.add_constraint(-self.MILP_IN[i]-self.MILP_IN[i+self.word_length]-self.MILP_OUT[i] >= -2)
                return self.milp
            if model_options.granularity == GRANULARITY.WORDWISE:
                # wordsize is set externally in wordbasedcipher.add_subcipher
                # and should NOT be confused with self.word_length
                for i in range(self.word_length // self.wordsize):
                    self.milp.add_constraint(-self.MILP_IN[i]+self.MILP_IN[i+self.word_length//self.wordsize]+self.MILP_OUT[i] >= 0)
                    self.milp.add_constraint(self.MILP_IN[i]-self.MILP_IN[i+self.word_length//self.wordsize]+self.MILP_OUT[i] >= 0)
                    self.milp.add_constraint(self.MILP_IN[i]+self.MILP_IN[i+self.word_length//self.wordsize]-self.MILP_OUT[i] >= 0)
                    # Skip fourth constraint as we are working with activity patterns instead of values
                return self.milp
            raise InvalidModelOptionException(
                model_options.granularity, GRANULARITY
            )
        if model_options.cryptanalysis == CRYPTANALYSIS.LINEAR:
            # Masks for the two inputs and the output need to be equal

            # wordsize is set externally in wordbasedcipher.add_subcipher
            if model_options.granularity == GRANULARITY.WORDWISE:
                divide_by = self.wordsize
            elif model_options.granularity == GRANULARITY.BITWISE:
                divide_by = 1
            else:
                raise InvalidModelOptionException(
                    model_options.granularity, GRANULARITY
                )

            for i in range(self.word_length // divide_by):
                # Masks for both inputs should be identical
                self.milp.add_constraint(
                    self.MILP_IN[i] ==
                    self.MILP_IN[i + self.word_length//divide_by]
                )
                # Output masks should also be the same
                self.milp.add_constraint(
                    self.MILP_IN[i] == self.MILP_OUT[i]
                )
            return self.milp
        raise InvalidModelOptionException(
            model_options.cryptanalysis, CRYPTANALYSIS
        )

    def _model_sat(self, model_options):
        """
        Models the XOR of two words by creating a MILP/SAT model of the
        feasibility region for the differential/linear transitions.

        INPUT:

            - ``model_options`` -- :class:`civerly.model_options.MODEL_OPTIONS`
              Option specifying the model to generate (e.g. using MILP or SAT,
              linear or differential cryptanaylsis,
              bit-wise or word-wise modeling).

        OUTPUT: A MILP/SAT model
        """
        self._init_model(model_options)
        if model_options.cryptanalysis == CRYPTANALYSIS.DIFFERENTIAL:

            n = self.word_length

            alpha = [self.SAT_IN[i] for i in range(n)]
            beta = [self.SAT_IN[i + n] for i in range(n)]
            gamma = [self.SAT_OUT[i] for i in range(n)]

            for i in range(n):
                self.sat.add_clause((alpha[i], beta[i], -gamma[i]))
                self.sat.add_clause((alpha[i], -beta[i], gamma[i]))
                self.sat.add_clause((-alpha[i], beta[i], gamma[i]))
                self.sat.add_clause((-alpha[i], -beta[i], -gamma[i]))

            return self.sat

        elif model_options.cryptanalysis == CRYPTANALYSIS.LINEAR:

            n = self.word_length

            alpha = [self.SAT_IN[i] for i in range(n)]
            beta = [self.SAT_IN[i + n] for i in range(n)]
            gamma = [self.SAT_OUT[i] for i in range(n)]

            for i in range(n):
                self.sat.add_clause((-alpha[i], beta[i]))
                self.sat.add_clause((alpha[i], -beta[i]))
                self.sat.add_clause((-alpha[i], gamma[i]))
                self.sat.add_clause((alpha[i], -gamma[i]))

            return self.sat


class ModAdd_CVL(Component):
    r"""
    Modular addition component. Accepts the vector :math:`x||y` and
    returns :math:`x \boxplus y`.

    INPUT:

        - ``word_length`` -- integer; Determines the word length.
          The evaluation map will map an input of size :math:`2 \cdot`
          ``word_length`` to an output of length ``word_length``.

        - ``name`` -- string; The component name for easier identification
          (optional).

    OUTPUT: An ``ModAdd_CVL`` instance of length ``word_length``.

    EXAMPLES::

        sage: from civerly.util import int_to_vec, vec_to_int
        sage: from civerly.component import ModAdd_CVL
        sage: modadd_component = ModAdd_CVL(32)
        sage: hex(vec_to_int(modadd_component(
        ....:   int_to_vec(0x11111111_12121212, 64)
        ....: )))
        '0x23232323'
    """
    def __init__(self, word_length, name=None):
        super().__init__(2*word_length, word_length, name=name)
        self.__word_length = word_length

    def eval(self, x):
        A = vec_to_int(x[:self.word_length])
        B = vec_to_int(x[self.word_length:])
        return int_to_vec((A + B) % (1 << self.word_length), self.word_length)

    @property
    def word_length(self):
        return self.__word_length

    def __repr__(self):
        if self.name is not None:
            return self.name
        return f"ModAdd({self.word_length})"

    def _to_dict(self):
        return {
            "type": "ModAdd_CVL",
            "name": self.name,
            "word_length": int(self.word_length),
        }

    @classmethod
    def _from_dict(cls, d):
        return cls(d["word_length"], name=d.get("name"))

    def _model_milp(self, model_options):
        raise InvalidModelOptionException(
            model_options.optimization,
            message="ModAdd_CVL is not supported in MILP"
        )

    def _model_sat(self, model_options):
        r"""
        Implementing the method from 'Nicky Mouha and Bart Preneel:
        Towards Finding Optimal Differential Characteristics for ARX:
        Application to Salsa20' (https://eprint.iacr.org/2013/328.pdf)

        A transition :math:`(\alpha, \beta) \rightarrow \gamma` is valid iff
        :math:`eq(\alpha \ll 1, \beta \ll 1, \gamma \ll 1) \land
        (\alpha \oplus \beta \oplus \gamma \oplus (\beta \ll 1)) = 0`,
        with :math:`eq(x,y,z) = (\bar{x} \oplus y) \land (\bar{x} \oplus z)`

        The corresponding weight of the differential is computed as follows:
        :math:`w(\alpha, \beta \rightarrow \gamma) =
        h^\ast(\overline{eq(\alpha, \beta, \gamma)})`

        """
        self._init_model(model_options)
        if model_options.cryptanalysis == CRYPTANALYSIS.DIFFERENTIAL:

            n = self.word_length

            alpha = [self.SAT_IN[i] for i in range(n)]
            beta = [self.SAT_IN[i + n] for i in range(n)]
            gamma = [self.SAT_OUT[i] for i in range(n)]

            # NOTE that alpha[n-1] is LSB and alpha[0] is MSB
            # Clauses for ModAdd (excluding LSB)
            for i in range(n - 1):
                self.sat.add_clause((alpha[i], beta[i], -gamma[i], alpha[i+1], beta[i+1], gamma[i+1]))
                self.sat.add_clause((alpha[i], -beta[i], gamma[i], alpha[i+1], beta[i+1], gamma[i+1]))
                self.sat.add_clause((-alpha[i], beta[i], gamma[i], alpha[i+1], beta[i+1], gamma[i+1]))
                self.sat.add_clause((-alpha[i], -beta[i], -gamma[i], alpha[i+1], beta[i+1], gamma[i+1]))
                self.sat.add_clause((alpha[i], beta[i], gamma[i], -alpha[i+1], -beta[i+1], -gamma[i+1]))
                self.sat.add_clause((alpha[i], -beta[i], -gamma[i], -alpha[i+1], -beta[i+1], -gamma[i+1]))
                self.sat.add_clause((-alpha[i], beta[i], -gamma[i], -alpha[i+1], -beta[i+1], -gamma[i+1]))
                self.sat.add_clause((-alpha[i], -beta[i], gamma[i], -alpha[i+1], -beta[i+1], -gamma[i+1]))

            self.sat.add_clause((alpha[n-1], beta[n-1], -gamma[n-1]))
            self.sat.add_clause((alpha[n-1], -beta[n-1], gamma[n-1]))
            self.sat.add_clause((-alpha[n-1], beta[n-1], gamma[n-1]))
            self.sat.add_clause((-alpha[n-1], -beta[n-1], -gamma[n-1]))

            PROB = [self.sat.var() for _ in range(n - 1)]

            # encode probability
            # ---------------------------------------------------------------------------
            for i in range(n - 1):
                self.sat.add_clause((-alpha[i+1], gamma[i+1], PROB[i]))
                self.sat.add_clause((beta[i+1], -gamma[i+1], PROB[i]))
                self.sat.add_clause((alpha[i+1], -beta[i+1], PROB[i]))
                self.sat.add_clause((alpha[i+1],  beta[i+1], gamma[i+1], -PROB[i]))
                self.sat.add_clause((-alpha[i+1], -beta[i+1], -gamma[i+1], -PROB[i]))

                self.sum_arr_sat += [
                    (1 * 10**model_options.sat_precision, PROB[i])
                ]
            # ---------------------------------------------------------------------------

        elif model_options.cryptanalysis == CRYPTANALYSIS.LINEAR:

            n = self.word_length

            alpha = [self.SAT_IN[i] for i in range(n)]
            beta = [self.SAT_IN[i + n] for i in range(n)]
            gamma = [self.SAT_OUT[i] for i in range(n)]
            PROB = [self.sat.var() for _ in range(n)]

            # PROB[0] == 0
            self.sat.add_clause((-PROB[0], ))

            # alpha[0] + beta[0] + gamma[0] + PROB[1] == 0
            self.sat.add_clause((alpha[0], beta[0], gamma[0], -PROB[1]))
            self.sat.add_clause((alpha[0], beta[0], -gamma[0], PROB[1]))
            self.sat.add_clause((alpha[0], -beta[0], gamma[0], PROB[1]))
            self.sat.add_clause((-alpha[0], beta[0], gamma[0], PROB[1]))
            self.sat.add_clause((alpha[0], -beta[0], -gamma[0], -PROB[1]))
            self.sat.add_clause((-alpha[0], beta[0], -gamma[0], -PROB[1]))
            self.sat.add_clause((-alpha[0], -beta[0], gamma[0], -PROB[1]))
            self.sat.add_clause((-alpha[0], -beta[0], -gamma[0], PROB[1]))

            # alpha[j+1] + beta[j+1] + gamma[j+1] + PROB[j+1] + PROB[j+2] == 0
            # for j in range(0, n-2)
            for j in range(1, n - 1):
                # From LinearLayer_CVL:
                self.sat.add_clause((alpha[j], beta[j], gamma[j], PROB[j], -PROB[j+1]))
                self.sat.add_clause((alpha[j], beta[j], gamma[j], -PROB[j], PROB[j+1]))
                self.sat.add_clause((alpha[j], beta[j], -gamma[j], PROB[j], PROB[j+1]))
                self.sat.add_clause((alpha[j], -beta[j], gamma[j], PROB[j], PROB[j+1]))
                self.sat.add_clause((-alpha[j], beta[j], gamma[j], PROB[j], PROB[j+1]))
                self.sat.add_clause((alpha[j], beta[j], -gamma[j], -PROB[j], -PROB[j+1]))
                self.sat.add_clause((alpha[j], -beta[j], gamma[j], -PROB[j], -PROB[j+1]))
                self.sat.add_clause((alpha[j], -beta[j], -gamma[j], PROB[j], -PROB[j+1]))
                self.sat.add_clause((alpha[j], -beta[j], -gamma[j], -PROB[j], PROB[j+1]))
                self.sat.add_clause((-alpha[j], beta[j], gamma[j], -PROB[j], -PROB[j+1]))
                self.sat.add_clause((-alpha[j], beta[j], -gamma[j], PROB[j], -PROB[j+1]))
                self.sat.add_clause((-alpha[j], beta[j], -gamma[j], -PROB[j], PROB[j+1]))
                self.sat.add_clause((-alpha[j], -beta[j], gamma[j], PROB[j], -PROB[j+1]))
                self.sat.add_clause((-alpha[j], -beta[j], gamma[j], -PROB[j], PROB[j+1]))
                self.sat.add_clause((-alpha[j], -beta[j], -gamma[j], PROB[j], PROB[j+1]))
                self.sat.add_clause((-alpha[j], -beta[j], -gamma[j], -PROB[j], -PROB[j+1]))

            for i in range(n):
                self.sat.add_clause((alpha[i], -gamma[i], PROB[i]))
                self.sat.add_clause((-alpha[i], gamma[i], PROB[i]))
                self.sat.add_clause((beta[i], -gamma[i], PROB[i]))
                self.sat.add_clause((-beta[i], gamma[i], PROB[i]))

                self.sum_arr_sat += [
                    (10**model_options.sat_precision, PROB[i])
                ]
        else:
            raise InvalidModelOptionException(
                model_options.cryptanalysis, CRYPTANALYSIS
                )

        return self.sat


class AND_CVL(Component):
    r"""
    ``AND_CVL`` component. Accepts the vector :math:`x||y` and returns :math:`x \& y`.

    INPUT:

        - ``word_length`` -- integer; Determines the word length.
          The evaluation map will map an input of size
          :math:`2 \cdot` ``word_length`` to an output of length
          ``word_length``.
        - ``name`` -- string; The component name for easier identification
          (optional)

    OUTPUT: An ``AND_CVL`` instance of length ``word_length``.

    EXAMPLES::

        sage: from civerly.util import int_to_vec, vec_to_int
        sage: from civerly.component import AND_CVL
        sage: and_component = AND_CVL(32)
        sage: hex(vec_to_int(and_component(
        ....:   int_to_vec(0x11111111_12121212,64)
        ....: )))
        '0x10101010'
    """
    def __init__(self, word_length, name=None):
        super().__init__(2*word_length, word_length, name=name)
        self.__word_length = word_length

    def eval(self, x):
        # Accepts a vector of length 2n ``x||y``, and returns ``x & y``.
        A = vec_to_int(x[:self.word_length])
        B = vec_to_int(x[self.word_length:])
        return int_to_vec(A & B, self.word_length)

    def __repr__(self):
        if self.name is not None:
            return self.name
        return f"And({self.word_length})"

    def _to_dict(self):
        return {
            "type": "AND_CVL",
            "name": self.name,
            "word_length": int(self.word_length),
        }

    @classmethod
    def _from_dict(cls, d):
        return cls(d["word_length"], name=d.get("name"))

    @property
    def word_length(self):
        return self.__word_length

    def _model_milp(self, model_options):
        raise InvalidModelOptionException(
            model_options.optimization,
            message="AND_CVL is not supported in MILP"
        )

    def _model_sat(self, model_options):
        r"""
        Treat the ``AND_CVL`` component as ``word_length`` many SBoxes with
        2 input bits and 1 output bit. In most cases this is a wrong
        assumption, which is why this modeling technique might yield incorrect
        results. The only case for which there exist a more accurate modeling
        is for inputs that are rotated (see https://eprint.iacr.org/2015/145).
        This is implemented in the dedicated class :class:`ROT_AND_CVL`.

        TESTS::

            sage: from civerly.component import AND_CVL
            sage: from civerly.model_options import *
            sage: from civerly.cipher import Cipher
            sage: from civerly.util import suppress_output
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   results = []
            ....:   N = 10
            ....:   for n in range(1, N+1):
            ....:     cipher = Cipher(2*n, n, name="and-doctest")
            ....:     node = cipher.add_subcipher(
            ....:         AND_CVL(n, name="and"),
            ....:         [(cipher.IN, (i, i)) for i in range(2*n)]
            ....:     )
            ....:     cipher.add_output([(node, (i, i)) for i in range(n)])
            ....:     model_options = MODEL_OPTIONS(
            ....:         cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:         optimization=OPTIMIZATION.SAT,
            ....:         granularity=GRANULARITY.BITWISE,
            ....:         sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:         sat_solver=CRYPTOMINISAT_CVL(),
            ....:         logic_minimizer=ESPRESSO_CVL(),
            ....:         path=Path(tmpdir))
            ....:     with suppress_output():
            ....:       result = cipher.analyse(model_options)
            ....:     results.append(result)
            ....:   print(results == [1]*N)
            True


        """

        self._init_model(model_options)

        # S(0, 0) = 0, S(0, 1) = 0, S(1, 0) = 0, S(1, 1) = 1
        and_sbox = SBox_CVL(SBox([0, 0, 0, 1]))

        # SBox(2 -> 1)
        assert and_sbox.input_length + and_sbox.output_length == 3
        one_bit_sbox_sat = and_sbox._model_sat(model_options)

        if model_options.cryptanalysis == CRYPTANALYSIS.DIFFERENTIAL:
            ddt = and_sbox.S.difference_distribution_table()
        elif model_options.cryptanalysis == CRYPTANALYSIS.LINEAR:
            # use LAT instead of DDT. The naming is not right here,
            # but it doesn't change the functionality
            ddt = [
                [abs(int(entry*len(and_sbox.S))) for entry in row]
                for row in and_sbox.S.linear_approximation_table("correlation")
            ]
        else:
            raise InvalidModelOptionException(
                model_options.cryptanalysis, CRYPTANALYSIS
            )

        # Contains the possible entries of ddt.
        set_ddt = sorted(list(set([d for dr in ddt for d in dr if d > 0])))

        PROB = [self.sat.var() for _ in range(len(set_ddt) * self.word_length)]

        for i in range(self.word_length):
            # combine left and right inputs and output of i'th and SBox
            VAR = [
                self.SAT_IN[i],
                self.SAT_IN[i+self.word_length],
                self.SAT_OUT[i]
            ] + PROB[i*len(set_ddt): (i + 1)*len(set_ddt)]

            for clause in one_bit_sbox_sat.clauses():
                new_clause = translate_sat_clause(VAR, clause[0])
                if new_clause not in [cl[0] for cl in self.sat.clauses()]:
                    self.sat.add_clause(new_clause)

        self.sum_arr_sat += [
            (-int(
                10**model_options.sat_precision
                * log2(set_ddt[i % len(set_ddt)] / ddt[0][0])
            ), PROBi)
            for i, PROBi in enumerate(PROB)
        ]

        return self.sat


class LinearLayer_CVL(Component):
    r"""
    The bitwise linear-layer component ``LinearLayer_CVL``.
    The main initialization parameter for the linear layer is the
    ``binary_matrix``. This describes the exact functionality as well as the
    ``input_length`` and ``output_length``, via its dimensions.

    INPUT:

        - ``binary_matrix`` -- A SageMath binary matrix; The binary matrix
          describing the components functionality.

        - ``branch_number_differential`` -- integer (optional); Specifies the
          differential branch number of the ``LinearLayer_CVL``. Must be
          specified to perform branch number based modeling for differential
          cryptanalysis. The branch number is understood wordwise.

        - ``branch_number_linear`` -- integer (optional); Specifies the linear
          branch number of the ``LinearLayer_CVL``. Must be specified to perform
          branch number based modeling for linear cryptanalysis. The branch
          number is understood wordwise.

        - ``name`` -- string (optional); Specifies the component name.

    OUTPUT: A ``LinearLayer_CVL`` component, which acts as a linear layer
    transforming bits.

    EXAMPLES::

        sage: from civerly.util import int_to_vec, vec_to_int
        sage: from civerly.component import LinearLayer_CVL
        sage: binmatrix = random_matrix(GF(2), 16)
        sage: while binmatrix.det() == 0: binmatrix = random_matrix(GF(2), 16)
        sage: linearlayer = LinearLayer_CVL(binmatrix)
        sage: hex(vec_to_int(linearlayer(int_to_vec(0xabcd, 16)))) # random
        '0x37c1'

    .. SEEALSO::
        - More on binary matrices:
          ``sage.matrix.matrix_mod2_dense.Matrix_mod2_dense``
    """
    def __init__(self, binary_matrix, branch_number_differential=None,
                 branch_number_linear=None, name=None):
        super().__init__(
            input_length=binary_matrix.ncols(),
            output_length=binary_matrix.nrows(),
            name=name
        )
        self.__branch_number_differential = branch_number_differential
        self.__branch_number_linear = branch_number_linear
        self.__binary_matrix = binary_matrix

    def eval(self, x):
        r"""
        Evaluating the ``LinearLayer_CVL`` component performs x --> Mx,
        i.e. it performs multiplication from the right.

        INPUT:

            - ``x`` -- Iterable; Describing the bit array of the input value.

        OUTPUT: The image of ``input_value`` under the transformation of
        ``binary_matrix``.
        """
        if not isinstance(x, (Iterable, Vector_mod2_dense)):
            raise TypeError(f"input is of type {type(x)}, should be Iterable.")

        return self.binary_matrix * x

    @property
    def binary_matrix(self):
        r"""
        Return the ``binary_matrix`` of ``self``.
        """
        return self.__binary_matrix

    @property
    def branch_number_differential(self):
        r"""
        Return the ``branch_number_differential`` of ``self``.

        This branch number is not computed, but simply accepted as an optional
        argument upon initialization.
        """
        return self.__branch_number_differential

    @property
    def branch_number_linear(self):
        r"""
        Return the ``branch_number_linear`` of ``self``.

        This branch number is not computed, but simply accepted as an optional
        argument upon initialization.
        """
        return self.__branch_number_linear

    def __repr__(self) -> str:
        if self.name is not None:
            return self.name
        return f"LL({self.input_length} -> {self.output_length})"

    def _to_dict(self):
        def _int_or_none(x):
            return int(x) if x is not None else None
        return {
            "type": "LinearLayer_CVL",
            "name": self.name,
            "binary_matrix": [
                [int(x) for x in row]
                for row in self.binary_matrix.rows()
            ],
            "branch_number_differential": _int_or_none(
                self.branch_number_differential
            ),
            "branch_number_linear": _int_or_none(self.branch_number_linear),
        }

    @classmethod
    def _from_dict(cls, d):
        from sage.matrix.constructor import Matrix as matrix
        mat = matrix(GF(2), d["binary_matrix"])
        return cls(
            mat,
            branch_number_differential=d["branch_number_differential"],
            branch_number_linear=d["branch_number_linear"],
            name=d.get("name"),
        )

    def inv(self):
        r"""Create the inverse of the current instance."""
        return LinearLayer_CVL(
            binary_matrix=self.binary_matrix.inverse(),
            name=self.name
        )

    def _model_milp(self, model_options):
        r"""
        """
        self._init_model(model_options)
        if model_options.granularity == GRANULARITY.WORDWISE:
            return self._milp_wordwise(model_options)
        elif model_options.granularity == GRANULARITY.BITWISE:
            return self._milp_bitwise(model_options)
        else:
            raise InvalidModelOptionException(
                model_options.granularity, GRANULARITY
            )

    def _model_sat(self, model_options):
        r"""
        """
        self._init_model(model_options)
        if model_options.granularity == GRANULARITY.BITWISE:
            return self._sat_bitwise(model_options)
        elif model_options.granularity == GRANULARITY.WORDWISE:
            raise InvalidModelOptionException(
                model_options.granularity,
                message="SAT-modeling does not support a wordwise granularity."
            )
        else:
            raise InvalidModelOptionException(
                model_options.granularity, GRANULARITY
            )

    def _milp_bitwise(self, model_options):
        r"""
        Bitwise LinearLayer modeling, by modeling each XOR. Using one of the
        following modeling techniques:

        - The standard Convex Hull modeling method.

        - Method using additional dummy variables.

        INPUT:

            - ``model_options`` -- see
              :class:`civerly.model_options.MODEL_OPTIONS`

        OUTPUT: An object ``MixedIntegerLinearProgram``, describing ``self``
        as a MILP.


        .. WARNING::
            The first method needs :math:`2^m` steps where :math:`m` is the
            highest Hamming weight over the rows of the binary matrix
            describing the linear layer. That is, this method is infeasible for
            large and dense linear layers.
        """

        if model_options.cryptanalysis == CRYPTANALYSIS.DIFFERENTIAL:
            binmatrix = self.binary_matrix
            MILP_IN = self.MILP_IN
            MILP_OUT = self.MILP_OUT
        elif model_options.cryptanalysis == CRYPTANALYSIS.LINEAR:
            # in linear cryptanalysis, transpose the matrix
            # and switch roles of input and output ( = "invert matrix")
            binmatrix = self.binary_matrix.transpose()
            MILP_IN = self.MILP_OUT
            MILP_OUT = self.MILP_IN
        else:
            raise InvalidModelOptionException(
                model_options.cryptanalysis, CRYPTANALYSIS
            )

        array_of_xorsums = []
        for row in binmatrix:
            xorsum = [i for i, e in enumerate(row) if e > 0]
            array_of_xorsums.append(tuple(xorsum))

        # Determine any missing inputs and add them into the dictionary
        # and set them to zero
        for i in range(binmatrix.ncols()):
            if all([i not in xorsum for xorsum in array_of_xorsums]):
                self.milp.add_constraint(MILP_IN[i] == 0)

        if model_options.linear_layer_modeling == \
                LINEAR_LAYER_MODELING.MORE_DUMMIES:
            MILP_DUMMY = self.milp.new_variable(name="MILP_DUMMY", binary=True)
            dummy_offset = 0
            for i, tup in enumerate(array_of_xorsums):
                ell = ceil(log2(len(tup) + 1))
                int_sum = sum([MILP_IN[t] for t in tup]) + MILP_OUT[i]
                binary_rep = sum([
                    (1 << (i + 1)) * MILP_DUMMY[dummy_offset + i]
                    for i in range(ell)
                ])
                dummy_offset += ell
                self.milp.add_constraint(int_sum == binary_rep)
        elif model_options.linear_layer_modeling == \
                LINEAR_LAYER_MODELING.CONVEX_HULL:
            for i, tup in enumerate(array_of_xorsums):
                posset = []  # set of possible transitions
                for j in range(1 << (len(tup)+1)):
                    # include all transitions with even hammingweight
                    if hw(j) % 2 == 0:
                        # x_1 + x_2 + x_3 = y_1, then 4.
                        posset.append(vector(ZZ, int_to_vec(j, len(tup) + 1)))
                convex_hull = Polyhedron(vertices=posset)

                constrs = convex_hull.inequalities() + convex_hull.equations()
                for constr in constrs:
                    assert all([self.input_length > u for u in (max(tup), i)])

                    # sub_constr : substituted constraints (with
                    # the appropiate variables)
                    sub_constr = constr[0] + sum(
                        constr[ind + 1] * MILP_IN[tup[ind]]
                        for ind in range(len(constr) - 2)
                    ) + constr[-1] * MILP_OUT[i]
                    if constr.is_inequality():
                        self.milp.add_constraint(sub_constr >= 0)
                    elif constr.is_equation():
                        self.milp.add_constraint(sub_constr == 0)
        else:
            raise InvalidModelOptionException(
                model_options.linear_layer_modeling,
                LINEAR_LAYER_MODELING
            )

        return self.milp

    def _milp_wordwise(self, model_options):
        r"""
        Implementing ``Generalized Word-wise MILP modeling`` technique and
        branch-number-based modeling of linear layers.

        INPUT:

            - ``model_options`` -- see
              :class:`civerly.model_options.MODEL_OPTIONS`

        OUTPUT: An object ``MixedIntegerLinearProgram``, describing ``self``
        as a MILP.
        """

        if model_options.linear_layer_modeling == \
                LINEAR_LAYER_MODELING.GENERALIZED_WORDWISE:
            posset = []  # possible set of transitions
            dimensions = []  # kernel-dimensions of each entry
            # wordsize is set externally in wordbasedcipher.add_subcipher

            vec_len_in = self.binary_matrix.ncols() // self.wordsize
            vec_len_out = self.binary_matrix.nrows() // self.wordsize
            # all-zero and all-ones vecs for lookup below
            all_vecs = ([0]*self.wordsize, [1]*self.wordsize)
            # Go over all input patterns
            for i in range(1 << vec_len_in):
                i_wordarr = [int(d) for d in f'{i:0{vec_len_in}b}']
                i_binarr = []
                for j in i_wordarr:
                    i_binarr += all_vecs[j]

                # Go over all output patterns
                for o in range(1 << vec_len_out):
                    o_wordarr = [int(d) for d in f'{o:0{vec_len_out}b}']
                    o_binarr = []
                    for j in o_wordarr:
                        o_binarr += all_vecs[j]

                    i_zero_inds, o_zero_inds = [], []
                    for pos in range(len(i_binarr)):
                        if i_binarr[pos] == 0:
                            i_zero_inds.append(pos)
                    for pos in range(len(o_binarr)):
                        if o_binarr[pos] == 0:
                            o_zero_inds.append(pos)

                    # matrix_to_be_solved is a submatrix of the linear layer,
                    # together with additional rows restricting the
                    # corresponding inputs to be zero
                    if model_options.cryptanalysis == \
                            CRYPTANALYSIS.DIFFERENTIAL:
                        matrix_to_be_solved = [
                            self.binary_matrix[j]
                            for j in range(self.binary_matrix.nrows())
                            if j in o_zero_inds
                        ]
                    elif model_options.cryptanalysis == CRYPTANALYSIS.LINEAR:
                        matrix_to_be_solved = [
                            self.binary_matrix.inverse().transpose()[j]
                            for j in range(self.binary_matrix.nrows())
                            if j in o_zero_inds
                        ]
                    else:
                        raise InvalidModelOptionException(
                            model_options.cryptanalysis,
                            CRYPTANALYSIS
                        )

                    # Append the additional rows forcing the corresponding
                    # input to be zero
                    for zero_index in i_zero_inds:
                        new_row = [0 for _ in range(self.binary_matrix.ncols())]
                        new_row[zero_index] = 1
                        matrix_to_be_solved.append(new_row)

                    vec_len_both = vec_len_in + vec_len_out
                    # Two special cases: [0,...,0], [1,...,1] are recognized
                    # as impossible (since the matrix is trivial then)
                    exceptions = ([0]*(vec_len_both), [1]*(vec_len_both))
                    is_exc = i_wordarr + o_wordarr in exceptions

                    current_dimension = matrix(
                        GF(2), matrix_to_be_solved
                    ).right_kernel().dimension()
                    dimensions.append(current_dimension)

                    # wordsize is set externally in
                    # wordbasedcipher.add_subcipher
                    predecessors = list_of_predecessor_vector_indices(
                        vector(GF(2), i_wordarr + o_wordarr), vec_len_both
                    )
                    # predecessors contains
                    # {u | u \prec (i_wordarr + o_wordarr)},
                    # with u \prec v <=> u_i \leq v_i \forall i

                    # Only a possible transition if the
                    # solution-space is **larger** than before
                    if (current_dimension > 0 and all([
                        current_dimension > dimensions[index_dim]
                        for index_dim in predecessors
                    ])) or is_exc:
                        posset.append(i_wordarr + o_wordarr)
            # --------------------------------------------------------------- #

            reduction_algorithm_ST17(self, posset, model_options)

        elif model_options.linear_layer_modeling == \
                LINEAR_LAYER_MODELING.BRANCH_NUMBER:

            if model_options.cryptanalysis == CRYPTANALYSIS.DIFFERENTIAL:
                bn = self.branch_number_differential
            elif model_options.cryptanalysis == CRYPTANALYSIS.LINEAR:
                bn = self.branch_number_linear
            else:
                raise InvalidModelOptionException(
                    model_options.cryptanalysis, CRYPTANALYSIS
                )

            if bn is None:
                raise ValueError(
                    "No branch number specified, specify it when "
                    "initializing the LinearLayer_CVL component."
                )

            ACTIVE = self.milp.new_variable(binary=True, name="ACTIVE")

            # wordsize is set externally in wordbasedcipher.add_subcipher
            words_in = self.input_length // self.wordsize
            words_out = self.output_length // self.wordsize
            self.milp.add_constraint(
                sum([self.MILP_IN[j] for j in range(words_in)])
                + sum([self.MILP_OUT[j] for j in range(words_out)])
                >= bn * ACTIVE[0]
            )

            # If one of the columns words is active, MixColumns will be active
            for j in range(words_in):
                self.milp.add_constraint(ACTIVE[0] >= self.MILP_IN[j])
            for j in range(words_out):
                self.milp.add_constraint(ACTIVE[0] >= self.MILP_OUT[j])

            self.milp.add_constraint(
                ACTIVE[0] <= sum(self.MILP_IN[j] for j in range(words_in))
            )
            self.milp.add_constraint(
                ACTIVE[0] <= sum(self.MILP_OUT[j] for j in range(words_out))
            )

        else:
            raise InvalidModelOptionException(
                model_options.linear_layer_modeling,
                LINEAR_LAYER_MODELING
            )
        return self.milp

    def _sat_bitwise(self, model_options):
        r"""
        Implementing the methods in SWW21 (see https://eprint.iacr.org/2021/213,
        section 2.3.1).

        TESTS::

            sage: from civerly.cipher import Cipher
            sage: from civerly.component import LinearLayer_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
            ....:   arr = [
            ....:     [1, 0, 0, 0],
            ....:     [0, 1, 0, 0],
            ....:     [0, 0, 1, 0],
            ....:     [0, 0, 0, 1],
            ....:     [0, 0, 0, 1],
            ....:     [0, 0, 1, 0],
            ....:     [0, 1, 0, 0],
            ....:     [1, 0, 0, 0]
            ....:   ]
            ....:   linearlayer = LinearLayer_CVL(matrix(GF(2), 8, 4, arr))
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     path=Path(tmpdir))
            ....:   cipher = Cipher(4, 8, name="LL-doctest")
            ....:   node = cipher.add_subcipher(
            ....:     linearlayer, [(cipher.IN, (i, i)) for i in range(4)]
            ....:   )
            ....:   cipher.add_output([(node, (i, i)) for i in range(8)])
            ....:   cipher.analyse(model_options)
            ....:   cipher.generate_report(model_options)
            ....:   arr = [
            ....:     [0, 0, 1, 1],
            ....:     [1, 0, 1, 1],
            ....:     [0, 1, 0, 0],
            ....:     [1, 1, 1, 0],
            ....:     [1, 1, 0, 0],
            ....:     [0, 0, 0, 0],
            ....:     [0, 1, 0, 0],
            ....:     [1, 0, 1, 1]
            ....:   ]
            ....:   mat = matrix(GF(2), 8, 4, arr)
            ....:   linearlayer = LinearLayer_CVL(mat, name=f"L(4 -> 8)")
            ....:   cipher = Cipher(4, 8, name="LL-doctest")
            ....:   node = cipher.add_subcipher(
            ....:     linearlayer, [(cipher.IN, (i, i)) for i in range(4)])
            ....:   cipher.add_output([(node, (i, i)) for i in range(8)])
            ....:   sat_model = cipher.model(model_options)  # assigned to suppress repr
            ....:   model_options.sat_solver.solve(
            ....:     Path(tmpdir) / 'LL-doctest.cnf',
            ....:     Path(tmpdir) / 'LL-doctest.sat',
            ....:     model_options)
            ....:   _ = cipher.get_trail(model_options)  # assigned to suppress repr
            48 variables and 89 clauses were written to '...'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 , 6] (trying w =   3) : SAT
            [  0 , 3] (trying w =   1) : SAT
            [  0 , 1] (trying w =   0) : SAT
            0
            Output file in: ...
            48 variables and 110 clauses were written to '...'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 , 6] (trying w =   3) : SAT
            [  0 , 3] (trying w =   1) : SAT
            [  0 , 1] (trying w =   0) : SAT
            0
        """

        if model_options.cryptanalysis == CRYPTANALYSIS.DIFFERENTIAL:
            mat = self.binary_matrix
            SAT_IN = self.SAT_IN
            SAT_OUT = self.SAT_OUT
        elif model_options.cryptanalysis == CRYPTANALYSIS.LINEAR:
            mat = self.binary_matrix.transpose()
            SAT_IN = self.SAT_OUT
            SAT_OUT = self.SAT_IN
        else:
            raise InvalidModelOptionException(
                model_options.cryptanalysis, CRYPTANALYSIS
            )

        if model_options.linear_layer_modeling == \
                LINEAR_LAYER_MODELING.EXCLUDE_ODD:
            for row_ind, row in enumerate(mat):
                active_entries = [i for i, e in enumerate(row) if e == 1]
                odd_hw_arr = []
                k = len(active_entries)
                # get all tuples with odd hamming weight
                for hamm in range(0, k+1, 2):
                    odd_hw_arr += hw_tau(k+1, hamm+1)

                VAR = [
                    SAT_IN[active_entries[i]] for i in range(k)
                ] + [SAT_OUT[row_ind]]
                for a in odd_hw_arr:
                    a_clause = (
                        (-1)**int(e) * (i+1)
                        for i, e in enumerate(f'{a:0{k+1}b}')
                    )
                    tup = translate_sat_clause(VAR, a_clause)
                    self.sat.add_clause(tup)
        elif model_options.linear_layer_modeling == \
                LINEAR_LAYER_MODELING.MORE_DUMMIES:

            # model each k-XOR as a sequence (k-1) of 2-XORs
            for row_ind, row in enumerate(mat):
                active_entries = [i for i, e in enumerate(row) if e == 1]
                if len(active_entries) == 0:
                    self.sat.add_clause((-SAT_OUT[row_ind], ))
                elif len(active_entries) == 1:
                    self.sat.add_clause((
                        -SAT_IN[active_entries[0]], SAT_OUT[row_ind],
                    ))
                    self.sat.add_clause((
                        SAT_IN[active_entries[0]], -SAT_OUT[row_ind],
                    ))
                else:
                    xor_model = XOR_CVL(1, name="xor")._model_sat(
                        model_options=model_options
                    )

                    current_node = SAT_IN[active_entries[0]]
                    for i in range(1, len(active_entries)-1):
                        # xor current_node with active_entries[i]
                        alpha = current_node
                        beta = SAT_IN[active_entries[i]]
                        gamma = self.sat.var()
                        for clause in xor_model.clauses():
                            self.sat.add_clause(
                                translate_sat_clause(
                                    [alpha, beta, gamma], clause[0]
                                )
                            )
                            current_node = gamma

                    alpha = current_node
                    beta = SAT_IN[active_entries[-1]]
                    gamma = SAT_OUT[row_ind]
                    for clause in xor_model.clauses():
                        self.sat.add_clause(
                            translate_sat_clause(
                                [alpha, beta, gamma], clause[0]
                            )
                        )

        else:
            raise InvalidModelOptionException(
                model_options.linear_layer_modeling, LINEAR_LAYER_MODELING
            )

        return self.sat


class PermuteLayer_CVL(LinearLayer_CVL):
    """
    The ``PermuteLayer_CVL`` class, accepting a permutation in form of a python
    list and converting it into the corresponding ``binary_matrix``,
    such that most of the functionality (except modeling) is inherited by
    ``LinearLayer_CVL``.

    INPUT:

        - ``perm`` -- list; Defines the permutation using the standard
          notation.

        - ``word_coarseness`` -- integer (optional); Specifies the size of the
          words on which the permutation should act on. For example, if set to
          1, a bit permutation is created; if set to 8, a byte permutation
          is created.

        - ``name`` -- string (optional); Specifies the component name.


    OUTPUT: A ``PermuteLayer_CVL`` component, which acts as a permutation on
    words of the size ``word_coarseness``.

    .. NOTE::
        ``perm`` starts its indexing at 0 (it is **not** a SageMath
        permutation).

    EXAMPLES::

        sage: from civerly.util import int_to_vec, vec_to_int
        sage: from civerly.component import PermuteLayer_CVL
        sage: perm = PermuteLayer_CVL([1, 3, 2, 0])
        sage: vec_to_int(perm(int_to_vec(0x9, 4)))
        12
    """
    def __init__(self, perm, word_coarseness=1, name=None):
        # convert perm to binary_matrix
        arr = [[0 for _ in range(len(perm))] for _ in range(len(perm))]
        for i in range(len(perm)):
            arr[perm[i]][i] = identity_matrix(word_coarseness)
        binary_matrix = block_matrix(GF(2), arr, subdivide=False)
        super().__init__(
            binary_matrix, branch_number_differential=2,
            branch_number_linear=2, name=name
        )
        self.__perm = perm
        self.__word_coarseness = word_coarseness

    @property
    def perm(self):
        return self.__perm

    @property
    def word_coarseness(self):
        return self.__word_coarseness

    def eval(self, x):
        return super().eval(x)

    def __repr__(self) -> str:
        if self.name is not None:
            return self.name
        return f"PL({self.input_length})"

    def _to_dict(self):
        return {
            "type": "PermuteLayer_CVL",
            "name": self.name,
            "perm": [int(x) for x in self.perm],
            "word_coarseness": int(self.word_coarseness),
        }

    @classmethod
    def _from_dict(cls, d):
        return cls(d["perm"], word_coarseness=d["word_coarseness"], name=d.get("name"))

    def inv(self):
        r"""
        Creates an inverse instance of ``self``.

        EXAMPLES::

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.component import PermuteLayer_CVL
            sage: perm = PermuteLayer_CVL([5, 4, 1, 0, 2, 3])
            sage: vec_to_int(perm(perm.inv()(int_to_vec(0x39, 6)))) == 0x39
            True
            sage: vec_to_int(perm.inv()(perm(int_to_vec(0x1c, 6)))) == 0x1c
            True

        """
        return PermuteLayer_CVL(
            perm=[
                q-1 for q in Permutation([p+1 for p in self.perm]).inverse()
            ],
            word_coarseness=self.word_coarseness,
            name=self.name
        )

    def _model_milp(self, model_options):
        r"""
        """
        self._init_model(model_options)
        if model_options.granularity == GRANULARITY.WORDWISE:
            # wordsize is set externally in wordbasedcipher.add_subcipher
            if self.word_coarseness == self.wordsize:
                for i in range(self.input_length // self.wordsize):
                    self.milp.add_constraint(
                        self.MILP_OUT[self.perm[i]] == self.MILP_IN[i]
                    )
                return self.milp
            else:
                return super()._model_milp(model_options)
        elif model_options.granularity == GRANULARITY.BITWISE:
            for i in range(self.input_length // self.word_coarseness):
                for j in range(self.word_coarseness):
                    self.milp.add_constraint(
                        self.MILP_OUT[self.word_coarseness * self.perm[i] + j]
                        == self.MILP_IN[self.word_coarseness * i + j]
                    )
            return self.milp
        else:
            raise InvalidModelOptionException(
                model_options.granularity, GRANULARITY
            )

    def _model_sat(self, model_options):
        r"""
        Generate the model for ``self``.

        INPUT:

            - ``model_options`` -- see
              :class:`civerly.model_options.MODEL_OPTIONS`

        OUTPUT: An object ``DIMACS``, describing ``self`` as a SAT.

        TESTS::

            sage: from civerly.model_options import *
            sage: from civerly.solvers import *
            sage: from civerly.component import PermuteLayer_CVL
            sage: perm = PermuteLayer_CVL([4, 3, 6, 1, 0, 2, 5, 7])
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.MILP,
            ....:   granularity=GRANULARITY.BITWISE)
            sage: perm.model(model_options)
            Boolean Program (no objective, 16 variables, 8 constraints)
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE)
            sage: model = perm.model(model_options)
            sage: (model.nvars(), len(model.clauses()))
            (16, 16)

        """
        self._init_model(model_options)
        if model_options.granularity == GRANULARITY.BITWISE:
            for i in range(self.input_length // self.word_coarseness):
                for j in range(self.word_coarseness):
                    self.sat.add_clause((
                        self.SAT_OUT[self.word_coarseness * self.perm[i] + j],
                        -self.SAT_IN[self.word_coarseness * i + j]
                    ))
                    self.sat.add_clause((
                        -self.SAT_OUT[self.word_coarseness * self.perm[i] + j],
                        self.SAT_IN[self.word_coarseness * i + j]
                    ))
            return self.sat
        else:
            raise InvalidModelOptionException(
                model_options.granularity,
                message="Wordwise modeling is not supported using SAT."
            )


class RotateLayer_CVL(PermuteLayer_CVL):
    """
    The ``RotateLayer_CVL`` class, accepting a rotation amount and translating
    it into the corresponding permutation, such that most of the functionality
    is inherited by ``PermuteLayer_CVL``.

    INPUT:

        - ``input_length`` -- integer; Determines the size of the rotation
          window.

        - ``r`` -- integer; Determines the rotation amount to the left, can
          be ``input_length`` at maximum.

        - ``word_coarseness`` -- integer (optional); Specifies the size of the
          words on which the rotation should act on. For example, if set to 1,
          bits will be rotated; if set to 8, each byte will be rotated

        - ``name`` -- string (optional); Specifies the component name.

    OUTPUT: A ``RotateLayer_CVL`` component, which acts as a rotation of words
    of the size ``word_coarseness``.

    .. NOTE::
        This layer rotates to the **left**, i.e. :math:`\\lll`

    EXAMPLES::

        sage: from civerly.util import vec_to_int, int_to_vec
        sage: from civerly.component import RotateLayer_CVL
        sage: rot = RotateLayer_CVL(16, 4)
        sage: vec_to_int(rot(int_to_vec(0x182b, 16)))
        33457
        sage: vec_to_int(rot(rot(rot(rot(
        ....:   int_to_vec(0x182b, 16)
        ....: ))))) == 0x182b
        True

    """
    def __init__(self, input_length, r, word_coarseness=1, name=None):
        # convert r rotation to perm
        self.__r = r
        perm = list(range((-r) % input_length, input_length)) + \
            list(range((-r) % input_length))
        super().__init__(perm, word_coarseness=word_coarseness, name=name)

    @property
    def r(self):
        return self.__r

    def eval(self, x):
        return super().eval(x)

    def __repr__(self) -> str:
        if self.name is not None:
            return self.name
        return f"RL({self.input_length})"

    def _to_dict(self):
        return {
            "type": "RotateLayer_CVL",
            "name": self.name,
            "input_length": int(self.input_length),
            "r": int(self.r),
            "word_coarseness": int(self.word_coarseness),
        }

    @classmethod
    def _from_dict(cls, d):
        return cls(
            d["input_length"], d["r"],
            word_coarseness=d["word_coarseness"],
            name=d.get("name"),
        )

    def inv(self):
        r"""
        Creates an inverse instance of ``self``.

        EXAMPLES::

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.component import RotateLayer_CVL
            sage: rot = RotateLayer_CVL(16, 3)
            sage: vec_to_int(rot(rot.inv()(int_to_vec(0x39, 16)))) == 0x39
            True
            sage: vec_to_int(rot.inv()(rot(int_to_vec(0x1c, 16)))) == 0x1c
            True

        """
        return RotateLayer_CVL(
            input_length=self.input_length,
            r=(self.input_length//self.word_coarseness) - self.r,
            word_coarseness=self.word_coarseness,
            name=self.name
        )


class SBox_CVL(Component):
    r"""
    The ``SBox_CVL`` class, implementing an SBox.

    INPUT:

        - ``S`` -- SageMath SBox; Determines the behaviour of the component.

        - ``name`` -- string (optional); Specifies the component name.

    OUTPUT: An ``SBox_CVL`` component.

    EXAMPLES::

        sage: from sage.crypto.sboxes import PRESENT
        sage: from civerly.util import int_to_vec, vec_to_int
        sage: from civerly.component import SBox_CVL
        sage: sb = SBox_CVL(PRESENT)
        sage: vec_to_int(sb(int_to_vec(0xd, 4)))
        7


    .. SEEALSO::
        - More on SageMath SBoxes: ``sage.crypto.sbox.SBox``
    """

    def __init__(self, S, name=None):
        super().__init__(S.input_size(), S.output_size(), name=name)
        self.__S = S

    def eval(self, x):
        # workaround for the fact that non-bijective SBoxes dont accept vectors
        return int_to_vec(self.__S(vec_to_int(x)), self.__S.output_size())

    @property
    def S(self):
        return self.__S

    def __repr__(self):
        if self.name is not None:
            return self.name
        return f"SBox({self.S.input_size()} -> {self.S.output_size()})"

    def _to_dict(self):
        return {
            "type": "SBox_CVL",
            "name": self.name,
            "S": [int(x) for x in self.S],
        }

    @classmethod
    def _from_dict(cls, d):
        return cls(SBox(d["S"]), name=d.get("name"))

    def _model_milp(self, model_options):
        self._init_model(model_options)
        if model_options.granularity == GRANULARITY.WORDWISE:
            # wordsize is set externally in wordbasedcipher.add_subcipher
            for i in range(self.input_length // self.wordsize):
                self.milp.add_constraint(self.MILP_OUT[i] == self.MILP_IN[i])
                self.sum_arr_milp += [(-1, f"IN[{i}]")]
            return self.milp
        elif model_options.granularity == GRANULARITY.BITWISE:
            return self._milp_bitwise(model_options)
        else:
            raise InvalidModelOptionException(
                model_options.granularity, GRANULARITY
            )

    def _model_sat(self, model_options):
        self._init_model(model_options)
        if model_options.granularity == GRANULARITY.BITWISE:
            return self._sat_bitwise(model_options)
        elif model_options.granularity == GRANULARITY.WORDWISE:
            raise InvalidModelOptionException(
                model_options.granularity,
                message="Wordwise modeling is not supported using SAT."
            )
        else:
            raise InvalidModelOptionException(
                model_options.granularity, GRANULARITY
            )

    def _milp_bitwise(self, model_options):
        r"""
        Bitwise SBox-Modeling is done by utilizing convex-hull based methods
        described in:

        - Yu Sasaki and Yosuke Todo: New Algorithm for Modeling S-box in {MILP}
        Based Differential and Division Trail Search
        (https://doi.org/10.1007/978-3-319-69284-5_11) or

        - Christina Boura and Daniel Coggia: Efficient MILP Modelings for
          Sboxes and Linear Layers of SPN ciphers
          (https://doi.org/10.13154/tosc.v2020.i3.327-361)

        TESTS:

            Test large-sbox modeling for toy cipher using a single SBox with a
            unique transition of (non-trivial) maximal probability::

                sage: from sage.crypto.sbox import SBox
                sage: from civerly.sboxcipher import SBoxCipher
                sage: from civerly.component import SBox_CVL
                sage: from civerly.model_options import *
                sage: from civerly.solvers import *
                sage: from civerly.util import suppress_output, vec_to_int
                sage: import tempfile
                sage: sb = SBox(
                ....:   (4, 0, 1, 8, 2, 5, 10, 7, 6, 9, 3, 11, 12, 13, 14, 15)
                ....: )
                sage: sbox = SBox_CVL(sb, "s-box")
                sage: cipher = SBoxCipher(4, 4, name="ToySingleSBoxCipher")
                sage: node = cipher.add_subcipher(
                ....:   sbox, [(cipher.IN, (i, i)) for i in range(4)]
                ....: )
                sage: cipher.add_output([(node, (i, i)) for i in range(4)])
                sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
                ....:   model_options = MODEL_OPTIONS(
                ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                ....:     optimization=OPTIMIZATION.MILP,
                ....:     granularity=GRANULARITY.BITWISE,
                ....:     sbox_modeling=SBOX_MODELING.DISTORTED_BALL,
                ....:     milp_solver=SCIP_CVL(),
                ....:     path=Path(tmpdir))
                ....:   with suppress_output():
                ....:     milp = cipher.analyse(model_options)
                ....:   results, objective_value = model_options.milp_solver._process_solution_file(
                ....:     model_options.path / (cipher.name + ".sol")
                ....:   )
                ....:   print(objective_value)
                ....:   in_diff  = vec_to_int(vector(
                ....:     GF(2), 4,
                ....:     [results['IN'][i] for i in range(4)]
                ....:   ))
                ....:   out_diff = vec_to_int(vector(
                ....:     GF(2), 4,
                ....:     [results['OUT'][i] for i in range(4)]
                ....:   ))
                ....:   ddt = sb.difference_distribution_table()
                ....:   print(ddt[in_diff][out_diff])
                ....:   print(ddt[in_diff][out_diff]/16.0 == 2**(-objective_value))
                1
                8
                True

            Test small-sbox modeling for toy cipher using a single SBox with a
            unique transition of (non-trivial) maximal probability::

                sage: from sage.crypto.sbox import SBox
                sage: from civerly.sboxcipher import SBoxCipher
                sage: from civerly.component import SBox_CVL
                sage: from civerly.model_options import *
                sage: from civerly.util import suppress_output, vec_to_int
                sage: import tempfile
                sage: sb = SBox(
                ....:   (4, 0, 1, 8, 2, 5, 10, 7, 6, 9, 3, 11, 12, 13, 14, 15)
                ....: )
                sage: sbox = SBox_CVL(sb, "s-box")
                sage: cipher = SBoxCipher(4, 4, name="ToySingleSBoxCipher")
                sage: node = cipher.add_subcipher(
                ....:   sbox, [(cipher.IN, (i, i)) for i in range(4)]
                ....: )
                sage: cipher.add_output([(node, (i, i)) for i in range(4)])
                sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
                ....:   model_options = MODEL_OPTIONS(
                ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                ....:     optimization=OPTIMIZATION.MILP,
                ....:     granularity=GRANULARITY.BITWISE,
                ....:     sbox_modeling=SBOX_MODELING.CONVEX_HULL,
                ....:     milp_solver=SCIP_CVL(),
                ....:     path=Path(tmpdir))
                ....:   with suppress_output():
                ....:     milp = cipher.model(model_options)
                ....:   model_options.milp_solver.solve(
                ....:     input_file=model_options.path / (cipher.name + ".mps"),
                ....:     solution_file=model_options.path / (cipher.name + ".sol"),
                ....:   )
                ....:   results, objective_value = model_options.milp_solver._process_solution_file(
                ....:     model_options.path / (cipher.name + ".sol"),
                ....:   )
                ....:   print(objective_value)
                ....:   in_diff  = vec_to_int(vector(
                ....:     GF(2), 4, [results['IN'][i] for i in range(4)]
                ....:   ))
                ....:   out_diff = vec_to_int(vector(
                ....:     GF(2), 4, [results['OUT'][i] for i in range(4)]
                ....:   ))
                ....:   ddt = sb.difference_distribution_table()
                ....:   print(ddt[in_diff][out_diff])
                ....:   print(ddt[in_diff][out_diff]/16.0 == 2**(-objective_value))
                1
                8
                True
        """
        solver = model_options.milp_solver

        if model_options.cryptanalysis == CRYPTANALYSIS.DIFFERENTIAL:
            ddt = self.S.difference_distribution_table()
        elif model_options.cryptanalysis == CRYPTANALYSIS.LINEAR:
            # use LAT instead of DDT. The naming is not right here,
            # but it doesn't change the functionality
            ddt = matrix([
                [abs(int(entry*len(self.S))) for entry in row]
                for row in self.S.linear_approximation_table("correlation")
            ])
        else:
            raise InvalidModelOptionException(
                model_options.cryptanalysis, CRYPTANALYSIS
            )

        # Contains the possible entries of ddt.
        set_ddt = sorted(list(set([d for dr in ddt for d in dr if d > 0])))

        PROB = self.milp.new_variable(name="PROB", binary=True)

        if model_options.sbox_modeling == SBOX_MODELING.DISTORTED_BALL:
            # Apply the method by Boura and Coggia. First, we compute a set of
            # inequations modeling the s-box transitions. As this test will be
            # quite large, we apply a reduction afterward to minimize the
            # number of equations used for the final model of the s-box.

            # Path to file for caching the original set of inequations
            s_file_name = ''.join([f'{s_entry:x}' for s_entry in self.S])
            s_file_ineq = model_options.path / (s_file_name + ".ineq.json")
            # Load inequations if we computed them already
            if os.path.exists(s_file_ineq):
                with open(s_file_ineq, "r") as ineq_file:
                    inequations_for_prob = json.load(ineq_file)
            else:  # Create inequations for s-box transitions
                # Originally, this method does not take the probability
                # of an s-box transition into account. Hence, the easiest way
                # to do so is the iterate for every non-zero probability
                # within the DDT and merge the resulting models while keeping
                # track of the probability.
                inequations_for_prob = dict()
                for prob in set_ddt:
                    if prob == 0:
                        continue
                    # prob needs to be a string to comply with json format
                    inequations_for_prob[str(prob)] = \
                        distorted_balls.get_inequations(ddt, prob)
                # Cache inequations
                with open(s_file_ineq, "w") as ineq_file:
                    json.dump(inequations_for_prob, ineq_file)

            # Compute all points that do not have a given probability.
            impossible_points_for_prob = {
                prob: [] for prob in inequations_for_prob.keys()
            }
            for a in range(1 << self.input_length):
                for b in range(1 << self.output_length):
                    for prob in impossible_points_for_prob.keys():
                        if ddt[a][b] != int(prob):
                            impossible_points_for_prob[prob].append((a, b))

            def removes(inequation, point):
                r"""
                Checks if inequation removes point
                :param inequation: List of coefficients representing an
                  inequation
                :param point: point of the form (in,out)
                :return: Whether inequation removes point
                """
                assert len(inequation) == self.input_length + self.output_length + 1, (
                    "ERROR: Length of inequation does not match "
                    f"(expected {self.input_length + self.output_length + 1}, "
                    f"got {len(inequation)})"
                )
                # Build left-hand side using coefficients given in inequation
                lhs = 0
                for i in range(self.input_length):
                    # the 0-th bit is the msb
                    lhs += ((point[0] >> i) & 1) * \
                        inequation[self.input_length - i - 1]
                for i in range(self.output_length):
                    # the 0-th bit is the msb
                    lhs += ((point[1] >> i) & 1) * \
                        inequation[self.input_length + self.output_length - i - 1]
                # Compare with right-hand size
                if lhs < inequation[-1]:
                    return True
                return False

            new_mps_files = []
            reduction_solution_files = dict()
            for prob, impossible_points in impossible_points_for_prob.items():
                s_file_mps = model_options.path / f"{s_file_name}.p{prob}.mps"
                s_file_sol = model_options.path / f"{s_file_name}.p{prob}.sol"
                reduction_solution_files[prob] = s_file_sol

                if os.path.exists(s_file_sol):
                    print(
                        f"Using existing file {s_file_sol}, "
                        "make sure it is up to date!"
                    )
                else:
                    # Generate the reduction-MILP and write into an .mps file
                    # In essence, we add equations to make sure that each
                    # impossible point is removed by at least one equation.
                    # Here, impossible means that the probability does not
                    # match the desired one.
                    milp_to_minimize_milp = MixedIntegerLinearProgram(
                        maximization=False, solver="GLPK")  # Reduction MILP
                    Z = milp_to_minimize_milp.new_variable(
                        name="Z", binary=True)
                    for point in impossible_points:
                        # Add a reduction inequation ensuring that each
                        # impossible point is removed by at least one
                        # inequation
                        milp_to_minimize_milp.add_constraint(
                            sum([
                                Z[ineq_index]
                                for ineq_index, inequation in enumerate(
                                    inequations_for_prob[prob]
                                )
                                if removes(inequation, point)
                            ]) >= 1
                        )

                    milp_to_minimize_milp.set_objective(sum(Z))
                    with suppress_output():  # to avoid doctest failure
                        milp_to_minimize_milp.write_mps(str(s_file_mps))
                    if not isinstance(solver, NO_MILP_SOLVER_CVL):
                        solver.solve(
                            input_file=s_file_mps, solution_file=s_file_sol
                        )
                    else:  # Remember filename so we can tell the user to solve it
                        new_mps_files.append(s_file_mps)

            if isinstance(solver, NO_MILP_SOLVER_CVL):
                print(
                    "SBox MILPs have been written to "
                    f"{', '.join(new_mps_files)}. "
                    "In order to continue the modeling, solve the generated "
                    "MILPs by providing solution files with the names "
                    f"{', '.join(new_mps_files).replace('.mps', '.sol')}."
                )
                self._return_immediately_ = True
                return

            selected_inequations = {
                prob: [] for prob in reduction_solution_files.keys()
            }
            for prob, s_file_sol in reduction_solution_files.items():
                assert os.path.exists(s_file_sol), (
                    "ERROR: Solution file missing despite a "
                    "former check or generation"
                )

                results, _ = model_options.milp_solver._process_solution_file(s_file_sol)
                assert 'Z' in results and len(results) == 1, (
                    "ERROR: Unexpected variables in results. "
                    f"Found {results.keys()}, expected 'Z'"
                )
                for ineq_index, use in results['Z'].items():
                    if use:  # if Z[ineq_index] was determined to be 1
                        selected_inequations[prob].append(inequations_for_prob[prob][ineq_index])

            for prob_str, sel_ineq in selected_inequations.items():
                prob_index = set_ddt.index(int(prob_str))
                for inequation in sel_ineq:
                    lhs = 0
                    for i in range(self.input_length):
                        lhs += self.MILP_IN[i] * inequation[i]
                    for i in range(self.output_length):
                        lhs += self.MILP_OUT[i] * inequation[self.input_length + i]
                    non_zero_coefficients = sum([i != 0 for i in inequation])
                    # To incorporate the probability we subtract
                    # non_zero_coefficients*128 from the right-hand side and
                    # add it to the left-hand side if the probability variable
                    # is set. This is motivated by the fact that the
                    # coefficients are int8 values in the C++ code and the
                    # equation will therefore always be fulfilled if the
                    # probability variable is zero, and it will match the
                    # original inequation otherwise.
                    lhs -= PROB[prob_index] * non_zero_coefficients * 128  # probability encoding bits
                    self.milp.add_constraint(lhs >= inequation[-1] - non_zero_coefficients * 128)

            # Add a constraint that at least one probability
            # variable needs to be one
            self.milp.add_constraint(sum(PROB) >= 1)

        else:
            posset = []
            for i in range(1 << self.input_length):
                for o in range(1 << self.output_length):
                    if ddt[i][o] > 0:
                        i_binarr = [int(bit) for bit in f'{i:0{self.input_length}b}']
                        o_binarr = [int(bit) for bit in f'{o:0{self.output_length}b}']

                        # p_arr is appended to the possible transitions to encode probability.
                        p_arr = [0 for _ in range(len(set_ddt))]
                        p_arr[set_ddt.index(ddt[i][o])] = 1
                        posset.append(i_binarr + o_binarr + p_arr)

            if model_options.sbox_modeling == SBOX_MODELING.CONVEX_HULL:
                # Convex Hull method by Sasaki and Todo
                # ----------------------------------------------------------------
                reduction_algorithm_ST17(
                    self, posset, model_options, PROB=PROB
                )
                # ----------------------------------------------------------------
            elif model_options.sbox_modeling == SBOX_MODELING.LOGICAL_COND:

                imposset = []
                clauses = []
                # compute imposset = complement of posset
                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
                L = self.input_length + self.output_length + len(set_ddt)
                for transition_int in range(1 << L):
                    if transition_int not in posset:
                        imposset.append(transition_int)
                # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
                for impossible_transition in imposset:
                    tup = (
                        (-1)**((impossible_transition >> (L - i - 1)) & 1)
                        * i
                        for i in range(L)
                    )
                    clauses.append(tup)

                n_in, n_out = self.input_length, self.output_length
                VAR = [self.MILP_IN[v] for v in range(n_in)] \
                    + [self.MILP_OUT[v] for v in range(n_out)] \
                    + [PROB[v] for v in range(len(set_ddt))]

                # translate SAT clauses into MILP constraints
                for clause in clauses:
                    constr = translate_sat_clause(VAR, clause)
                    # the rhs computes the hammingweight of the currently
                    # processed transition vector
                    self.milp.add_constraint(
                        sum(constr) >= 1 - sum(
                            [1 if lit < 0 else 0 for lit in clause]
                        )
                    )
                # ----------------------------------------------------------------

            elif model_options.sbox_modeling == SBOX_MODELING.LOGICAL_COND_ESPRESSO:
                # Espresso minimization (logical conditioning)
                # ----------------------------------------------------------------
                esp_file_name = f"espresso-{zlib.crc32("".join([
                    str(int("".join(map(str, pos)), 2))
                    for pos in sorted(posset)
                ]).encode("utf-8")):x}"  # rule for espresso file names
                esp_file_in = model_options.path / f"{esp_file_name}_in.pla"
                esp_file_out = model_options.path / f"{esp_file_name}_out.pla"

                if os.path.exists(esp_file_out):
                    print(
                        f"Using existing file {esp_file_out}, "
                        "make sure it is up to date!"
                    )
                else:
                    _write_espresso_input(
                        posset, esp_file_name, model_options.path
                    )
                    if isinstance(model_options.logic_minimizer, NO_LOGIC_MINIMIZER_CVL):
                        print(
                            "Optimization problem for Espresso has been "
                            f"written to {esp_file_in}.\n"
                            "In order to minimize the clauses, execute:\n\n"
                            "\t> espresso -epos "
                            f"{esp_file_in} > {esp_file_out}"
                        )
                        self._return_immediately_ = True
                        return
                    elif isinstance(model_options.logic_minimizer, ESPRESSO_CVL):
                        model_options.logic_minimizer.solve(
                            esp_file_in, esp_file_out
                        )

                clauses = _read_espresso_output(esp_file_out)

                n_in, n_out = self.input_length, self.output_length
                VAR = [self.MILP_IN[v] for v in range(n_in)] \
                    + [self.MILP_OUT[v] for v in range(n_out)] \
                    + [PROB[v] for v in range(len(set_ddt))]

                # translate SAT clauses into MILP constraints
                for clause in clauses:
                    constr = translate_sat_clause(VAR, clause)
                    # the rhs computes the hammingweight of the currently
                    # processed transition vector
                    self.milp.add_constraint(
                        sum(constr) >= 1 - sum(
                            [1 if lit < 0 else 0 for lit in clause]
                        )
                    )
                # ----------------------------------------------------------------

        # Extend sum_arr_milp with the correct weights
        self.sum_arr_milp += [
            (log2(set_ddt[i] / ddt[0][0]), f"PROB[{i}]")
            for i in range(len(set_ddt))
        ]
        return self.milp

    def _sat_bitwise(self, model_options):
        r"""
        Generates the SAT constraints describing the differential or linear
        transitions through ``self.S``.

        Test large-sbox modeling for toy cipher using a single SBox with a
        unique transition of (non-trivial) maximal probability::

            sage: from sage.crypto.sbox import SBox
            sage: from civerly.sboxcipher import SBoxCipher
            sage: from civerly.component import SBox_CVL
            sage: from civerly.model_options import *
            sage: from civerly.util import suppress_output, vec_to_int
            sage: import tempfile
            sage: sb = SBox((4, 0, 1, 8, 2, 5, 10, 7, 6, 9, 3, 11, 12, 13, 14, 15))
            sage: sbox = SBox_CVL(sb, "s-box")
            sage: cipher = SBoxCipher(4, 4, name="ToySingleSBoxCipher")
            sage: node = cipher.add_subcipher(sbox, [(cipher.IN, (i, i)) for i in range(4)])
            sage: cipher.add_output([(node, (i, i)) for i in range(4)])
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   with suppress_output(): cipher.analyse(model_options)
            ....:   results, objective_value = model_options.sat_solver._process_solution_file(
            ....:     model_options.path / (cipher.name + ".sat")
            ....:   )
            ....:   print(objective_value)
            ....:   in_diff  = vec_to_int(
            ....:     vector(GF(2), 4, [results[i+1] for i in range(4)])
            ....:   )
            ....:   out_diff = vec_to_int(
            ....:     vector(GF(2), 4, [results[i+5] for i in range(4)])
            ....:   )
            ....:   print(sb.difference_distribution_table()[in_diff][out_diff])
            ....:   print(sb.difference_distribution_table()[in_diff][out_diff]/16.0
            ....:         == 2**(-int(objective_value)))
            1
            8
            True


        """

        if model_options.cryptanalysis == CRYPTANALYSIS.DIFFERENTIAL:
            ddt = self.S.difference_distribution_table()
        elif model_options.cryptanalysis == CRYPTANALYSIS.LINEAR:
            # use LAT instead of DDT. The naming is not right here,
            # but it doesn't change the functionality
            ddt = [
                [abs(int(entry*len(self.S))) for entry in row]
                for row in self.S.linear_approximation_table("correlation")
            ]
        else:
            raise InvalidModelOptionException(
                model_options.cryptanalysis, CRYPTANALYSIS
            )

        # Contains the possible entries of ddt.
        set_ddt = sorted(list(set([d for dr in ddt for d in dr if d > 0])))

        posset = []

        for i in range(1 << self.input_length):
            for o in range(1 << self.output_length):
                if ddt[i][o] > 0:
                    i_binarr = [int(bit) for bit in f'{i:0{self.input_length}b}']
                    o_binarr = [int(bit) for bit in f'{o:0{self.output_length}b}']

                    # p_arr is appended to the possible transitions to encode
                    # probability.
                    p_arr = [0 for _ in range(len(set_ddt))]
                    p_arr[set_ddt.index(ddt[i][o])] = 1
                    posset.append(tuple(i_binarr + o_binarr + p_arr))

        PROB = [self.sat.var() for _ in range(len(set_ddt))]
        SAT_VARS = self.SAT_IN + self.SAT_OUT + PROB

        # espresso minimization
        # ------------------------------------------------------------
        if model_options.sbox_modeling == SBOX_MODELING.LOGICAL_COND_ESPRESSO:
            # Espresso minimization (logical conditioning)
            # ----------------------------------------------------------------
            esp_file_name = f"espresso-{zlib.crc32("".join([
                str(int("".join(map(str, pos)), 2))
                for pos in sorted(posset)
            ]).encode("utf-8")):x}"  # rule for espresso file names
            esp_file_in = model_options.path / f"{esp_file_name}_in.pla"
            esp_file_out = model_options.path / f"{esp_file_name}_out.pla"

            if os.path.exists(esp_file_out):
                print(
                    f"Using existing file {esp_file_out}, "
                    "make sure it is up to date!"
                )
            else:
                _write_espresso_input(
                    posset, esp_file_name, model_options.path
                )
                if isinstance(model_options.logic_minimizer, NO_LOGIC_MINIMIZER_CVL):
                    print(
                        "Optimization problem for Espresso has been "
                        f"written to '{esp_file_in}'.\n"
                        "In order to minimize the clauses, execute:\n\n"
                        "\t$ espresso -epos "
                        f"{esp_file_in} > {esp_file_out}"
                    )
                    self._return_immediately_ = True
                    return
                elif isinstance(model_options.logic_minimizer, ESPRESSO_CVL):
                    model_options.logic_minimizer.solve(
                        esp_file_in, esp_file_out
                    )

            clauses = _read_espresso_output(esp_file_out)

            for clause in clauses:
                self.sat.add_clause(translate_sat_clause(SAT_VARS, clause))
        # ------------------------------------------------------------

        # No reduction
        # ------------------------------------------------------------
        elif model_options.sbox_modeling == SBOX_MODELING.LOGICAL_COND:
            imposset = []
            # compute imposset = complement of posset
            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
            L = len(SAT_VARS)
            for transition_int in range(1 << L):
                if transition_int not in posset:
                    imposset.append(transition_int)
            # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ #
            for impossible_transition in imposset:
                tup = (
                    (-1)**((impossible_transition >> (L - i - 1)) & 1)
                    * SAT_VARS[i]
                    for i in range(L)
                )
                self.sat.add_clause(tup)
        else:
            raise InvalidModelOptionException(
                model_options.sbox_modeling,
                SBOX_MODELING
            )
        # ------------------------------------------------------------

        self.sum_arr_sat += [
            (-int(
                10**model_options.sat_precision
                * log2(set_ddt[i] / ddt[0][0])
            ), PROB[i])
            for i in range(len(set_ddt))
        ]

        return self.sat


class ROT_AND_CVL(Component):
    r"""

    This component is specially designed for SIMON-like ciphers.
    It allows for more precise results when modeling with SAT, since assuming
    independent inputs when modeling ``AND_CVL`` gives highly unrealistic
    results, especially when in reality the inputs are highly dependent on
    each other.

    EXAMPLES::

        sage: from civerly.component import ROT_AND_CVL
        sage: from civerly.util import int_to_vec, vec_to_int
        sage: ra = ROT_AND_CVL(16, 5, name="ra")
        sage: vec_to_int(ra(int_to_vec(0x7451, 16)))
        0
        sage: vec_to_int(ra(int_to_vec(0x1821, 16)))
        33


    TESTS::

        sage: import random
        sage: from civerly.util import int_to_vec
        sage: from civerly.andrx import AndRX
        sage: from civerly.component import ROT_AND_CVL, RotateLayer_CVL, AND_CVL
        sage: arr = []
        sage: for _ in range(10):
        ....:   n = random.randint(2, 64)
        ....:   r = random.randint(1, n-1)
        ....:   ra = ROT_AND_CVL(n, r=r, name="ra")
        ....:   rot_comp = RotateLayer_CVL(n, r)
        ....:   and_comp = AND_CVL(n)
        ....:   ra_cipher = AndRX(n, 1, 1, name="ra_cipher")
        ....:   node = ra_cipher.add_subcipher(rot_comp, [(ra_cipher.IN, (0, 0))])
        ....:   node = ra_cipher.add_subcipher(and_comp, [(ra_cipher.IN, (0, 0)), (node, (0, 1))])
        ....:   ra_cipher.add_output([(node, (0, 0))])
        ....:   plaintext = int_to_vec(random.randint(0, (1 << n) - 1), n)
        ....:   arr.append(ra_cipher(plaintext) == ra(plaintext))
        sage: all(arr)
        True


    """
    def __init__(self, word_length, r, name=None):
        assert r % word_length != 0, f"{r} must be non-zero mod {word_length}!"
        super().__init__(word_length, word_length, name=name)
        self.__word_length = word_length
        self.__r = r % self.word_length

    @property
    def word_length(self):
        return self.__word_length

    @property
    def r(self):
        return self.__r

    def eval(self, x):
        # Accepts a vector of length n ``x``, and returns ``x & (x <<< r)``.
        A = vec_to_int(x)
        B = vec_to_int(list(x[self.r % self.word_length:]) + list(x[:self.r % self.word_length]))
        return int_to_vec(A & B, self.word_length)

    def __repr__(self):
        if self.name is not None:
            return self.name
        return f"ROT_AND({self.word_length}, {self.r})"

    def _to_dict(self):
        return {
            "type": "ROT_AND_CVL",
            "name": self.name,
            "word_length": int(self.word_length),
            "r": int(self.r),
        }

    @classmethod
    def _from_dict(cls, d):
        return cls(d["word_length"], d["r"], name=d.get("name"))

    def _model_milp(self, model_options) -> MixedIntegerLinearProgram:
        raise InvalidModelOptionException(
            model_options.optimization,
            message="ROT_AND_CVL is not supported in MILP"
        )

    def _model_sat(self, model_options) -> DIMACS:
        r"""
        Important NOTE: The case alpha = (1, ..., 1) is neglected!

        We assume ``self.r`` to be co-prime with ``self.word_length``.
        """
        self._init_model(model_options)

        if model_options.cryptanalysis == CRYPTANALYSIS.LINEAR:
            rot_comp = RotateLayer_CVL(self.word_length, self.r, name="rot_comp")
            and_comp = AND_CVL(self.word_length, name="and_comp")
            rot_sat = rot_comp._model_sat(model_options)
            and_sat = and_comp._model_sat(model_options)

            # create the variables
            ROT_VAR = [self.sat.var() for _ in range(rot_sat.nvars())]
            AND_VAR = [self.sat.var() for _ in range(and_sat.nvars())]

            for clause in rot_sat.clauses():
                self.sat.add_clause(translate_sat_clause(ROT_VAR, clause[0]))
            for clause in and_sat.clauses():
                self.sat.add_clause(translate_sat_clause(AND_VAR, clause[0]))

            for i in range(self.word_length):
                # branching self.SAT_IN --> (rot_comp.SAT_IN, and_comp.SAT_IN)
                assert rot_comp.SAT_IN[i] == i+1
                assert and_comp.SAT_IN[i] == i+1
                assert (rot_comp.SAT_OUT[i] == self.word_length + i+1), (
                    f"{rot_comp.SAT_OUT[i]} != {self.word_length + i+1}"
                )
                assert (and_comp.SAT_OUT[i] == 2*self.word_length + i+1), (
                    f"{and_comp.SAT_OUT[i]} != {2*self.word_length + i+1}"
                )

                self.sat.add_clause((self.SAT_IN[i], ROT_VAR[i], -AND_VAR[i]))
                self.sat.add_clause((self.SAT_IN[i], -ROT_VAR[i], AND_VAR[i]))
                self.sat.add_clause((-self.SAT_IN[i], ROT_VAR[i], AND_VAR[i]))
                self.sat.add_clause((-self.SAT_IN[i], -ROT_VAR[i], -AND_VAR[i]))

                # rot_comp.SAT_OUT --> and_comp.SAT_IN
                self.sat.add_clause((-ROT_VAR[i + self.word_length], AND_VAR[i + self.word_length]))
                self.sat.add_clause((ROT_VAR[i + self.word_length], -AND_VAR[i + self.word_length]))

                # and_comp.SAT_OUT --> self.SAT_OUT
                self.sat.add_clause((-AND_VAR[i + 2*self.word_length], self.SAT_OUT[i]))
                self.sat.add_clause((AND_VAR[i + 2*self.word_length], -self.SAT_OUT[i]))

            self.sum_arr_sat += [
                (i[0], AND_VAR[i[1]-1])
                for i in and_comp.sum_arr_sat
            ]

            return self.sat

        elif model_options.cryptanalysis == CRYPTANALYSIS.DIFFERENTIAL:

            gcd_result = gcd(self.r, self.word_length)
            if gcd_result > 1:  # If ``self.r`` divides ``self.word_length``
                small_ra = ROT_AND_CVL(
                    word_length=self.word_length//gcd_result,
                    r=self.r//gcd_result,
                    name="small_ra"
                )
                small_sat = small_ra._model_sat(model_options=model_options)
                VAR = [self.sat.var() for _ in range(gcd_result * small_sat.nvars())]

                for i in range(gcd_result):
                    for clause in small_sat.clauses():
                        new_clause = translate_sat_clause(
                            VAR[i*small_sat.nvars(): (i+1)*small_sat.nvars()],
                            clause[0]
                        )
                        self.sat.add_clause(new_clause)

                    for input_index in range(small_ra.input_length):
                        self.sat.add_clause((self.SAT_IN[gcd_result * input_index + i], -VAR[input_index + i * small_sat.nvars()]))
                        self.sat.add_clause((-self.SAT_IN[gcd_result * input_index + i], VAR[input_index + i * small_sat.nvars()]))
                    for output_index in range(small_ra.output_length):
                        self.sat.add_clause((self.SAT_OUT[gcd_result * output_index + i], -VAR[output_index + small_ra.input_length + i * small_sat.nvars()]))
                        self.sat.add_clause((-self.SAT_OUT[gcd_result * output_index + i], VAR[output_index + small_ra.input_length + i * small_sat.nvars()]))

                    self.sum_arr_sat += [
                        (factor, VAR[index-1 + i * small_sat.nvars()])
                        for factor, index in small_ra.sum_arr_sat
                    ]

                return self.sat

            w = self.word_length

            alpha = self.SAT_IN
            beta = self.SAT_OUT

            varibits = [self.sat.var() for _ in range(w)]
            doublebits = [self.sat.var() for _ in range(w)]
            SUM_VAR = [self.sat.var() for _ in range(w)]
            ALPHA_ALL_ONES = self.sat.var()

            # If alpha = (1, ..., 1), set dummy-variable to 1
            self.sat.add_clause(
                tuple([-alpha[i] for i in range(w)] + [ALPHA_ALL_ONES])
            )

            # NOTE: Forbid alpha = (1, ..., 1)
            # If the case alpha = (1, ..., 1) should be handled, remove the
            # constraint below and add the appropiate ones
            ###########################################
            self.sat.add_clause((-ALPHA_ALL_ONES, ))  #
            ###########################################

            for i in range(w):
                # definition of varibits
                self.sat.add_clause((-alpha[i],                           varibits[i]))
                self.sat.add_clause((-alpha[(i + self.r) % w], varibits[i]))
                self.sat.add_clause((alpha[i], alpha[(i + self.r) % w], -varibits[i]))

                # definition of doublebits
                self.sat.add_clause((alpha[i], -doublebits[i]))  # ( a, -d)
                self.sat.add_clause((-alpha[(i + self.r) % w], -doublebits[i]))  # (-b, -d)
                self.sat.add_clause((alpha[(i + 2*self.r) % w], -doublebits[i]))  # ( c, -d)
                self.sat.add_clause((-alpha[i], alpha[(i + self.r) % w], -alpha[(i + 2*self.r) % w], doublebits[i]))  # (-a, b, -c, d)

                # constraint that must hold for non-zero prob
                self.sat.add_clause((-beta[i], varibits[i]))
                self.sat.add_clause((beta[i], -beta[(i + self.r) % w], -doublebits[i]))
                self.sat.add_clause((-beta[i], beta[(i + self.r) % w], -doublebits[i]))

                # weight = sum(varibits[i] + doublebits[i] for i in range(w))
                self.sat.add_clause((varibits[i], doublebits[i], -SUM_VAR[i]))
                self.sat.add_clause((varibits[i], -doublebits[i], SUM_VAR[i]))
                self.sat.add_clause((-varibits[i], doublebits[i], SUM_VAR[i]))
                self.sat.add_clause((-varibits[i], -doublebits[i], -SUM_VAR[i]))

                self.sum_arr_sat += [
                    (1 * 10**model_options.sat_precision, SUM_VAR[i])
                ]

        return self.sat
