r"""
``Cipher`` is the base class of all ciphers in CiVerLy.
A ``Cipher`` is either a directed acyclic multigraph of sub-ciphers, or a
fundamental component (see :class:`civerly.component.Component`).
This allows for a recursive graph structure, simplifying the process of
constructing and analysing a cipher.
It is possible to evaluate a correctly built cipher in order to test it with
test vectors.
However, the main functionality of the ``Cipher`` object is to model the graph
as a MILP or SAT constraint system, which includes multiple modeling
techniques.
The multigraph of the ``Cipher`` object consists of nodes representing the
sub-ciphers, as well as edges, indicating on a bitwise level in what way the
components are connected.

EXAMPLES::

    sage: from civerly.util import vec_to_int, int_to_vec
    sage: from civerly.cipher import Cipher
    sage: cipher = Cipher(32, 32, name="cipher")
    sage: cipher
    cipher: 32 -> 32 bits
        Sub ciphers:
    sage: from civerly.component import I_CVL
    sage: identity = I_CVL(32, name="identity")
    sage: edges = [(cipher.IN, (i, i)) for i in range(32)]
    sage: node = cipher.add_subcipher(identity, edges)
    sage: cipher
    cipher: 32 -> 32 bits
        Sub ciphers:
        1: identity: 32 -> 32 bits
    sage: cipher.add_output([(node, (i, i)) for i in range(32)])
    sage: hex(vec_to_int(cipher(int_to_vec(0x11119999, 32))))
    '0x11119999'
"""

import glob
import json
import subprocess
import time
from collections.abc import Iterable
from copy import deepcopy
from dataclasses import replace
from math import ceil, sqrt

from sage.modules.free_module_element import vector
from sage.modules.vector_mod2_dense import Vector_mod2_dense
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.sat.solvers.dimacs import DIMACS

from civerly.component import Component
from civerly.model_options import (
    CRYPTANALYSIS,
    GRANULARITY,
    OPTIMIZATION,
    InvalidModelOptionException,
)
from civerly.trail import TrailNode
from civerly.util import suppress_output, translate_sat_clause


class CipherNotValidException(Exception):
    def __init__(self):
        r"""
        Exception which is thrown whenever the cipher is not finished, i.e.
        not all outputs are connected, while it is required to continue the
        program flow.
        """
        super().__init__(
            "The cipher is not finished yet, "
            "as not all outputs are connected. "
            "Use '.add_output()' to be able to call."
        )


class Cipher:
    class __Special_Node(Component):
        r"""
        A special "component" representing the input or output of
        ``cipher_instance``, which is not directly accessible from the outside.
        When initialising a cipher, it will contain this input node by default.
        """

        def __init__(self, cipher_instance, in_node=True):
            r"""
            Code similar to the tests below should never be written by the
            user, as the special node type should not be accessed from outside.

            TESTS::

                sage: from civerly.cipher import Cipher
                sage: cipher = Cipher(4, 4, name="cipher")
                sage: isinstance(cipher.IN, Cipher._Cipher__Special_Node)
                True
                sage: isinstance(cipher.OUT, Cipher._Cipher__Special_Node)
                True

            """
            self._cipher_wordsize = cipher_instance._wrd
            self._return_immediately_ = False
            self.sum_arr_milp = []
            self.sum_arr_sat = []
            self.results = []
            if in_node:
                self.__name = f"{cipher_instance.name}.IN"
                self.__input_length = cipher_instance.input_length
                self.__output_length = cipher_instance.input_length
            else:
                self.__name = f"{cipher_instance.name}.OUT"
                self.__input_length = cipher_instance.output_length
                self.__output_length = cipher_instance.output_length
            self.in_node = in_node

        def __hash__(self):
            return hash((self.in_node, self.input_length, self.output_length))

        def __eq__(self, other):
            return hash(self) == hash(other)

        def __lt__(self, other):
            if type(self) is type(other):
                return self.name < other.name
            return True

        def __gt__(self, other):
            if type(self) is type(other):
                return self.name > other.name
            return False

        def __repr__(self) -> str:
            r"""
            Return ``self.name`` when ``self`` is printed.

            TESTS::

                sage: from civerly.cipher import Cipher
                sage: cipher = Cipher(4, 4, name="cipher")
                sage: print(cipher.IN)
                cipher.IN
                sage: print(cipher.OUT)
                cipher.OUT

            """
            return self.name

        @property
        def input_length(self):
            r"""
            Return ``self.__input_length`` whenever
            ``self.input_length`` is accessed.

            TESTS::

                sage: from civerly.cipher import Cipher
                sage: cipher = Cipher(3, 5, name="cipher")
                sage: cipher.IN.input_length
                3
                sage: cipher.OUT.input_length
                5

            """
            assert self.__input_length > 0
            return int(self.__input_length)

        @property
        def output_length(self):
            r"""
            Return ``self.__output_length`` whenever
            ``self.output_length`` is accessed.

            TESTS::

                sage: from civerly.cipher import Cipher
                sage: cipher = Cipher(3, 5, name="cipher")
                sage: cipher.IN.output_length
                3
                sage: cipher.OUT.output_length
                5

            """
            assert self.__output_length > 0
            return int(self.__output_length)

        @property
        def name(self):
            r"""
            Return ``self.__name`` whenever
            ``self.name`` is accessed.

            TESTS::

                sage: from civerly.cipher import Cipher
                sage: cipher = Cipher(3, 5, name="test-cipher")
                sage: cipher.IN.name
                'test-cipher.IN'

            """
            assert isinstance(self.__name, str)
            return self.__name

        def eval(self, x):
            r"""
            Evaluate ``self`` on input ``x``. The special nodes act trivially
            on ``x``.

            TESTS::

                sage: from civerly.cipher import Cipher
                sage: cipher = Cipher(3, 5, name="test-cipher")
                sage: cipher.IN.eval(vector(GF(2), [1, 1, 0]))
                (1, 1, 0)
                sage: cipher.OUT.eval(vector(GF(2), [1, 0, 0, 1, 0]))
                (1, 0, 0, 1, 0)

            """
            assert len(x) == self.input_length, (
                f"Wrong input size {len(x)}, must be {self.input_length}"
            )
            return x

        def model(self, model_options, *args, **kwargs):
            """
            Return the model for ``self``.
            """
            return Component.model(self, model_options)

        def _model_milp(self, model_options):
            r"""
            Generate and return the MILP model for ``self``, which is trivial
            for special nodes.

            TESTS::

                sage: from civerly.cipher import Cipher
                sage: from civerly.model_options import *
                sage: cipher = Cipher(3, 5, name="test-cipher")
                sage: model_options = MODEL_OPTIONS(
                ....:   cryptanalysis=CRYPTANALYSIS.LINEAR,
                ....:   optimization=OPTIMIZATION.MILP,
                ....:   granularity=GRANULARITY.BITWISE
                ....: )
                sage: cipher.IN._model_milp(model_options)
                Boolean Program (no objective, 6 variables, 3 constraints)
                sage: cipher.OUT._model_milp(model_options)
                Boolean Program (no objective, 10 variables, 5 constraints)

            """
            Component._init_model(self, model_options)
            if model_options.granularity == GRANULARITY.WORDWISE:
                for i in range(self.input_length // self._cipher_wordsize):
                    self.milp.add_constraint(self.MILP_OUT[i] == self.MILP_IN[i])
            elif model_options.granularity == GRANULARITY.BITWISE:
                for i in range(self.input_length):
                    self.milp.add_constraint(self.MILP_OUT[i] == self.MILP_IN[i])
            else:
                raise InvalidModelOptionException(
                    model_options.granularity, GRANULARITY
                )
            return self.milp

        def _model_sat(self, model_options):
            r"""
            Generate and return the SAT model for ``self``, which is trivial
            for special nodes.

            TESTS::

                sage: from civerly.cipher import Cipher
                sage: from civerly.model_options import *
                sage: cipher = Cipher(3, 5, name="test-cipher")
                sage: model_options = MODEL_OPTIONS(
                ....:   cryptanalysis=CRYPTANALYSIS.LINEAR,
                ....:   optimization=OPTIMIZATION.SAT,
                ....:   granularity=GRANULARITY.BITWISE
                ....: )
                sage: model = cipher.IN._model_sat(model_options)
                sage: (model.nvars(), len(model.clauses()))
                (6, 6)
                sage: model = cipher.OUT._model_sat(model_options)
                sage: (model.nvars(), len(model.clauses()))
                (10, 10)

            """
            Component._init_model(self, model_options)
            if model_options.granularity == GRANULARITY.BITWISE:
                for i in range(self.input_length):
                    self.sat.add_clause((-self.SAT_OUT[i], self.SAT_IN[i]))
                    self.sat.add_clause((self.SAT_OUT[i], -self.SAT_IN[i]))
                return self.sat
            else:
                raise InvalidModelOptionException(
                    model_options.granularity, GRANULARITY
                )

        def _copy_over_dictionaries_recursively(self, prev, model_options):
            return

        def _to_dict(self):
            return {"type": "__Special_Node"}

        def _to_tikz(self, _comps=[]):
            return ""

    # --------- static variables
    # placeholder for the indices of outputs that not connected yet.
    NOT_SET = None

    def __init__(self, input_length, output_length, name, key_schedule=None):
        r"""
        Initialize ``self`` with the given parameters.

        Upon initialization, the cipher is a multigraph containing one node
        ``self.IN``, representing the input of the cipher.
        Furthermore, it initializes an empty list ``outputs`` which resembles
        which bits of which components form the output.

        INPUT:

            - ``input_length`` -- integer; Represents the block size (number of
              bits) on the input.

            - ``output_length`` -- integer; Represents the block size (number
              of bits) on the output.

            - ``name`` -- string; Used to name and identify the Cipher instance
              and for naming files that are written to disk.

            - ``key_schedule`` -- :class:`civerly.keyschedule.KeySchedule`
              (optional); Key schedule instance used by
              :meth:`set_round_keys` to derive round keys from a master key.
              Defaults to ``None``.

        OUTPUT: The instantiated ``Cipher`` with the following attributes:

            - ``input_length`` -- integer, public + immutable; Attribute set by
              the parameter of same name.

            - ``output_length`` -- integer, public + immutable; Attribute set
              by the parameter of same name.

            - ``name`` -- string public + immutable; Used to name and identify
              the ``Cipher`` instance and for naming files that are written to
              disk.

            - ``is_valid`` -- bool, private; Used to indicate whether the
              Cipher has been finished building, as otherwise the output has no
              incoming nodes (see :attr:`is_valid`).

            - ``IN``-- integer, public + immutable; The node label of the input
              node.

            - ``nodes`` -- list, private; List containing all nodes of the
              graph. Initialized such that it contains the input-node
              ``self.IN``.

            - ``edges`` -- list, private; List containing all edges of the
              graph. Empty when initialized.

            - ``outputs`` -- list, private: List containing the node indices
              that represent the output bits.

        An edge is of the form ``((a, b), (x, y))``, which corresponds to the
        fact that the ``x``-th bit of node ``a`` is connected with the ``y``-th
        bit of node ``b``.

        TESTS::

            sage: from civerly.cipher import Cipher
            sage: Cipher(5, 2, name="test-cipher")
            test-cipher: 5 -> 2 bits
                Sub ciphers:
            sage: Cipher(812, 127, name="test-cipher")
            test-cipher: 812 -> 127 bits
                Sub ciphers:
            sage: Cipher(0, 2, name="test-cipher")
            Traceback (most recent call last):
            ...
            AssertionError
            sage: Cipher(3, 0, name="test-cipher")
            Traceback (most recent call last):
            ...
            AssertionError

        .. NOTE::

            An edge is directed, meaning that
            ``((a, b), (x, y)) != ((b, a), (y, x))``.
            Furthermore, an edge must fulfill that :math:`a < b` in order to
            avoid cycles in the graph.
        """

        # initialization of private variables
        self.__input_length = input_length
        self.__output_length = output_length
        self.__name = name

        # self._wrd is used for generate_report, to determine the displayed
        # wordsize. Any subclass of WordBasedCipher will overwrite this value
        # with `self.wordsize`
        self._wrd = getattr(self, "_wrd", 4)

        self.__is_valid = False
        self.__IN = Cipher.__Special_Node(self, in_node=True)
        self.__OUT = Cipher.__Special_Node(self, in_node=False)
        self.__nodes = [self.IN]  # list of subciphers in this cipher
        self.__edges = []
        self.__outputs = [Cipher.NOT_SET] * self.__output_length

        # self.results stores all trails found by analyse() when
        # number_of_solutions > 1. Each entry is a dict
        # {"in": [...], "out": [...], "weight": <value>}.
        self.results = []

        # self.trail_nodes stores the TrailNode objects built during
        # analyse() for number_of_solutions > 1, one per solution.
        # Used by generate_report() and get_trail() to avoid re-reading
        # solution files.
        self.trail_nodes = []

        self.key_schedule = key_schedule

        self.milp = None
        self.sat = None
        self.X = None

        # attributes to keep timing information (in seconds)
        self._analyse_time = None
        self._model_time = None
        self._solve_time = None

    # Get-functions of various attributes:
    # --------------------------------------------------

    @property
    def input_length(self):
        r"""
        Return ``self.__input_length`` whenever ``self.input_length``
        is called.

        TESTS::

            sage: from civerly.cipher import Cipher
            sage: cipher = Cipher(812, 127, name="test-cipher")
            sage: cipher.input_length
            812

        """
        assert self.__input_length > 0
        return int(self.__input_length)

    @property
    def output_length(self):
        r"""
        Return ``self.__output_length`` whenever ``self.output_length``
        is called.

        TESTS::

            sage: from civerly.cipher import Cipher
            sage: cipher = Cipher(812, 127, name="test-cipher")
            sage: cipher.output_length
            127

        """
        assert self.__output_length > 0
        return int(self.__output_length)

    @property
    def IN(self):
        r"""
        Return ``self.__IN`` whenever ``self.IN``
        is called.

        TESTS::

            sage: from civerly.cipher import Cipher
            sage: cipher = Cipher(812, 127, name="test-cipher")
            sage: cipher.IN
            test-cipher.IN

        """
        assert isinstance(self.__IN, Cipher.__Special_Node)
        return self.__IN

    @property
    def OUT(self):
        r"""
        Return ``self.__OUT`` whenever ``self.OUT``
        is called.

        TESTS::

            sage: from civerly.cipher import Cipher
            sage: cipher = Cipher(812, 127, name="test-cipher")
            sage: cipher.OUT
            test-cipher.OUT

        """
        assert isinstance(self.__OUT, Cipher.__Special_Node)
        return self.__OUT

    @property
    def name(self):
        r"""
        Return ``self.__name`` whenever ``self.name``
        is called.

        TESTS::

            sage: from civerly.cipher import Cipher
            sage: cipher = Cipher(812, 127, name="test-cipher")
            sage: cipher.name
            'test-cipher'

        """
        assert isinstance(self.__name, str)
        return self.__name

    @property
    def nodes(self):
        r"""
        Return ``self.__nodes`` whenever ``self.nodes``
        is called.

        TESTS::

            sage: from civerly.cipher import Cipher
            sage: cipher = Cipher(812, 127, name="test-cipher")
            sage: cipher.nodes
            [test-cipher.IN]

        """
        assert isinstance(self.__nodes, list)
        return self.__nodes

    @property
    def edges(self):
        r"""
        Return ``self.__edges`` whenever ``self.edges``
        is called.

        TESTS::

            sage: from civerly.cipher import Cipher
            sage: cipher = Cipher(812, 127, name="test-cipher")
            sage: cipher.edges
            []

        """
        assert isinstance(self.__edges, list)
        return self.__edges

    @property
    def outputs(self):
        r"""
        Return ``self.__outputs`` whenever ``self.outputs``
        is called.

        TESTS::

            sage: from civerly.cipher import Cipher
            sage: cipher = Cipher(812, 127, name="test-cipher")
            sage: cipher.outputs == [None]*cipher.output_length
            True

        """
        assert isinstance(self.__outputs, list)
        return self.__outputs

    @property
    def is_valid(self):
        r"""
        A boolean variable indicating whether all outputs of ``self`` have been
        connected.
        It is only possible to execute ``eval``, ``model``, etc. if its value
        is ``True``
        (see :meth:`add_output` for details on how to achieve this).
        """
        assert isinstance(self.__is_valid, bool)
        return self.__is_valid

    def set_round_keys(self, k: int):
        r"""
        Derive round keys from master key ``k`` and inject them into the
        cipher's round key components.

        Requires ``self.key_schedule`` and ``self._rk_components`` to be
        set on the cipher instance (see :class:`civerly.keyschedule.KeySchedule`).
        After calling this method, ``self.eval(plaintext)`` returns the
        correct ciphertext for the given key.

        Modeling is unaffected - round key components retain their canonical
        behavior regardless of the value set here.

        INPUT:

            - ``k`` -- integer; the master key

        EXAMPLES::

            sage: from civerly.cipher_implementations.hurdle import HURDLE_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: hurdle = HURDLE_CVL(R=1)
            sage: hurdle.set_round_keys(0x99990099991188992277993366994455)
            sage: vec_to_int(hurdle(int_to_vec(0x222266662222eeee, 64))) == \
            ....:   0x09cc2a7e2222eeee
            True
        """
        if not hasattr(self, "_rk_components"):
            raise AttributeError(
                f"{self.name} has no _rk_components attribute. "
                f"Set self._rk_components to the list of RK_CVL components "
                f"in the cipher's __init__ to enable set_round_keys()."
            )
        if self.key_schedule is None:
            raise NotImplementedError(
                f"{self.name} has no key schedule implemented. "
                f"Omit set_round_keys() to use the default zero-key behavior."
            )
        rks = self.key_schedule(k)
        for comp, val in zip(self._rk_components, rks):
            comp.const = val

    @property
    def analyse_time(self):
        r"""
        Return the time it took to analyse ``self`` (in seconds).

        Analysing includes modeling and solving.
        """
        return self._analyse_time

    @property
    def model_time(self):
        r"""Return the time it took to model ``self`` (in seconds)."""
        return self._model_time

    @property
    def solve_time(self):
        r"""Return the time it took to solve the model for ``self`` (in seconds)."""
        return self._solve_time

    def add_subcipher(self, sub_cipher, edges):
        r"""
        Insert ``sub_cipher`` as a node into the graph, and connects the
        incoming nodes with it (given by ``edges``). The output of
        ``sub_cipher`` is not connected any further.

        INPUT:

            - ``sub_cipher`` -- Cipher; The sub-cipher to be added.

            - ``edges`` -- list; The edges connecting the previous nodes with
              ``sub_cipher``.

        OUTPUT:

            - The node index of the newly added ``sub_cipher``.

        Each entry in the ``edges`` list is of the form ``(a,(x,y))``, where
        ``a`` represents the index of the node which will be connected to the
        inputs of ``sub_cipher``. More precisely, the ``x``-th bit of ``a``
        will be connected to the ``y``-th bit of ``sub_cipher``.

        EXAMPLES::

            sage: from sage.crypto.sbox import SBox
            sage: from civerly.cipher import Cipher
            sage: from civerly.component import SBox_CVL
            sage: cipher = Cipher(9, 9, "Cipher")
            sage: sb  = SBox_CVL(SBox([0, 6, 1, 4, 2, 3, 5, 7]))
            sage: sb2 = SBox_CVL(SBox([5, 6, 7, 1, 2, 0, 4, 3]))
            sage: edges = [(cipher.IN, (i, i)) for i in range(3)]
            sage: node = cipher.add_subcipher(sb, edges)
            sage: edges = [(cipher.IN, (i + 3, i)) for i in range(3)]
            sage: node = cipher.add_subcipher(sb, edges)
            sage: edges = [(cipher.IN, (i + 6, i)) for i in range(3)]
            sage: node = cipher.add_subcipher(sb2, edges)
            sage: cipher
            Cipher: 9 -> 9 bits
                Sub ciphers:
                1: Unnamed Component: 3 -> 3 bits
                2: Unnamed Component: 3 -> 3 bits
                3: Unnamed Component: 3 -> 3 bits
        """
        # If self.OUT is in self.nodes and we "invalidate" the cipher again
        if len(edges) != sub_cipher.input_length:
            raise IndexError(f"{len(edges) = } != {sub_cipher.input_length = }")

        if sub_cipher != self.OUT:
            if self.is_valid:
                # remove the OUT-node (if this is a standard call of
                # ``add_subcipher``)
                self.__nodes.remove(self.OUT)
            self.__is_valid = False
        self.__nodes.append(deepcopy(sub_cipher))

        if sub_cipher == self.OUT:
            # we need to update self.OUT with its deepcopy
            self.__OUT = self.nodes[-1]

        n = len(self.nodes) - 1
        for a, (x, y) in edges:
            # Usually, a should be an integer (the index denoting the node to
            # be added). An exception is a == self.IN, which is not an integer,
            # but still valid here (for convenience)
            if isinstance(a, Cipher.__Special_Node):
                self.__add_edge(((self.nodes.index(a), n), (x, y)))
            else:
                self.__add_edge(((a, n), (x, y)))

        return n

    def __add_edge(self, edge):
        r"""
        Private function to insert an edge into the Cipher-graph. Is not
        intended to be used from the outside, but rather by
        :meth:`add_subcipher`.
        """
        (a, b), (x, y) = edge

        for existing_edge in self.edges:
            (aa, bb), (xx, yy) = existing_edge
            assert (bb, yy) != (b, y), (
                "Another edge already goes into that index of the node: "
                f"{(bb, yy)} == {(b, y)}"
            )

        if a != self.nodes.index(self.IN):
            assert a < b, (
                f"The nodes do not fulfill {a} < {b}. "
                "This could lead to a cycle in the graph, "
                "and is therefore not allowed."
            )
            assert x >= 0 and x < self.nodes[a].output_length, (
                "Desired connection on previous node failed "
                f"(Should be {x} < {self.nodes[a].output_length})"
            )
        assert y >= 0 and y < self.nodes[b].input_length, (
            "Desired connection on current node failed "
            f"(Should be {y} < {self.nodes[b].input_length})"
        )
        self.__edges.append(edge)

    def __call__(self, input_value):
        r"""
        See :meth:`eval`.
        """
        return self.eval(input_value)

    def eval(self, plaintext):
        r"""
        Evaluate ``self`` on input ``plaintext``.

        Evaluating a cipher is only possible after all outputs have been
        connected by :meth:`add_output`. If not, an error will be thrown.

        INPUT:

            - ``plaintext`` -- binary vector; The input to be evaluated. Must
              have the appropiate dimension (``input_length``) in order to
              succeed.

        OUTPUT:

            - The evaluation of ``self`` on ``input_value`` in form of a binary
              vector.

        .. SEEALSO::

            - Converting integers to binary vectors and vice versa:
              :meth:`civerly.util.vec_to_int` and
              :meth:`civerly.util.int_to_vec`
            - More on binary vectors:
              :class:`sage.modules.vector_mod2_dense.Vector_mod2_dense`

        EXAMPLES::

            sage: from civerly.util import vec_to_int, int_to_vec
            sage: from civerly.cipher import Cipher
            sage: from civerly.component import SBox_CVL
            sage: from sage.crypto.sbox import SBox as SBox_sage
            sage: cipher = Cipher(9, 9, name="Cipher")
            sage: sb = SBox_CVL(SBox_sage([0, 6, 1, 4, 2, 3, 5, 7]))
            sage: edges = [(cipher.IN, (i, i)) for i in range(3)]
            sage: node_s0 = cipher.add_subcipher(sb, edges)
            sage: edges = [(cipher.IN, (i + 3, i)) for i in range(3)]
            sage: node_s1 = cipher.add_subcipher(sb, edges)
            sage: edges = [(cipher.IN, (i + 6, i)) for i in range(3)]
            sage: node_s2 = cipher.add_subcipher(sb, edges)

        Now, calling ``cipher`` results in an exception::

            sage: vec_to_int(cipher(int_to_vec(0x52, 9)))
            Traceback (most recent call last):
            ...
            civerly.cipher.CipherNotValidException:
            The cipher is not finished yet, as not all outputs are connected.
            Use '.add_output()' to be able to call.


        In order to be able call, connect the output::

            sage: cipher.add_output([(node_s0, (i, i)) for i in range(3)])
            sage: cipher.add_output([(node_s1, (i, i + 3)) for i in range(3)])
            sage: cipher.add_output([(node_s2, (i, i + 6)) for i in range(3)])
            sage: hex(vec_to_int(cipher(int_to_vec(0x52, 9))))
            '0x189'
        """
        if not isinstance(plaintext, (Iterable, Vector_mod2_dense)):
            raise TypeError("Wrong type, input must be Vector_mod2_dense")
        if self.is_valid is False:
            raise CipherNotValidException()
        assert len(plaintext) == self.input_length, (
            f"(len(plaintext)) {len(plaintext)} "
            f"!= {self.input_length} (self.input_length)"
        )

        # first, eval all nodes
        evals = []
        # input of self.nodes[i] can only depend on inputs and self.nodes[j]
        # where j < i
        for i, v in enumerate(self.nodes):
            if v == self.IN:
                continue

            input_current_node = [Cipher.NOT_SET] * v.input_length
            for (a, b), (x, y) in self.edges:
                if b == i:
                    if a == self.nodes.index(self.IN):
                        input_current_node[y] = plaintext[x]
                    else:
                        input_current_node[y] = evals[a - 1][x]
            assert Cipher.NOT_SET not in input_current_node
            evals.append(v.eval(vector(GF(2), input_current_node)))

        # collect output
        output = [Cipher.NOT_SET] * self.output_length
        for c, (a, b) in enumerate(self.outputs):
            if a == self.nodes.index(self.IN):
                output[c] = plaintext[b]
            else:
                output[c] = evals[a - 1][b]
        e = "Evaluation failed, not all outputs have been collected."
        assert Cipher.NOT_SET not in output, e
        return vector(GF(2), output)

    def add_output(self, edges):
        r"""
        Connect the ``x``-th bit of node ``a`` in the graph to the ``y`` output
        bit.

        INPUT:

            - ``edges`` -- list of tuples; The edges that will be connected, in
              form of a list ``[(a, (x, y))]``.

            Each entry of ``edges`` has the following entries:
              - ``a`` -- integer; The index of the node that will be connected.
              - ``x`` -- integer; The bit position of node ``a`` which will be
                connected.
              - ``y`` -- integer; The bit position of the output which will be
                connected.

        OUTPUT: None. The ``y``-th output bit is now connected.


        EXAMPLES::

            sage: from civerly.cipher import Cipher
            sage: from civerly.component import SBox_CVL
            sage: from sage.crypto.sbox import SBox
            sage: cipher = Cipher(9, 9, "Cipher")
            sage: sb = SBox_CVL(SBox([0, 6, 1, 4, 2, 3, 5, 7]))
            sage: edges = [(cipher.IN, (i, i)) for i in range(3)]
            sage: node_s0 = cipher.add_subcipher(sb, edges)
            sage: edges = [(cipher.IN, (i + 3, i)) for i in range(3)]
            sage: node_s1 = cipher.add_subcipher(sb, edges)
            sage: edges = [(cipher.IN, (i + 6, i)) for i in range(3)]
            sage: node_s2 = cipher.add_subcipher(sb, edges)
            sage: cipher.is_valid
            False
            sage: cipher.add_output([(node_s0, (i, i)) for i in range(3)])
            sage: cipher.is_valid
            False
            sage: cipher.add_output([(node_s1, (i, i + 3)) for i in range(3)])
            sage: cipher.is_valid
            False
            sage: cipher.add_output([(node_s2, (i, i + 6)) for i in range(3)])
            sage: cipher.is_valid
            True

        .. NOTE::

            Not calling this function correctly (or at all) leads to an error
            upon evaluation.
        """
        for a, (x, y) in edges:
            e = f"{y} must be < {self.output_length}"
            assert y < self.output_length, e
            if a != self.IN:
                e = (
                    "Node has invalid index: It should hold that "
                    f"{a} < {len(self.__nodes)}"
                )
                assert a < len(self.nodes), e
                e = "Invalid index. You probably use a wrong node-variable to connect."
                assert x < self.nodes[a].output_length, e
                self.__outputs[y] = (a, x)
            else:
                self.__outputs[y] = (self.nodes.index(a), x)

        self.__is_valid = Cipher.NOT_SET not in self.outputs
        if self.is_valid:
            # Add the self.OUT node (using Cipher.add_subcipher, to avoid weird
            # behaviour from cipher subclasses)
            edges = [(a, (x, y)) for y, (a, x) in enumerate(self.outputs)]
            Cipher.add_subcipher(self, self.OUT, edges)

    def __eq__(self, other) -> bool:
        r"""
        Function for comparing two Cipher instances.

        EXAMPLES::

            sage: from sage.crypto.sboxes import AES
            sage: from civerly.component import SBox_CVL
            sage: from civerly.cipher import Cipher
            sage: s8 = SBox_CVL(AES)
            sage: cipher1 = Cipher(128, 128, name="Cipher_one")
            sage: edges = [(cipher1.IN, (i+8, i)) for i in range(8)]
            sage: node_s8 = cipher1.add_subcipher(s8, edges)
            sage: cipher2 = Cipher(128, 128, name="Cipher_two")
            sage: edges = [(cipher2.IN, (i+8, i)) for i in range(8)]
            sage: node_s8 = cipher2.add_subcipher(s8, edges)
            sage: cipher1 == cipher2
            True
            sage: cipher2.add_output([(node_s8, (i, i+120)) for i in range(8)])
            sage: cipher1 == cipher2
            False
        """
        if isinstance(other, Cipher):
            return hash(self) == hash(other)
        return False

    def __hash__(self):
        r"""
        Hash all the elements in ``self.__dict__`` that come directly from
        ``Cipher`` (not from any subclass!).
        This is to make all subclasses of ``Cipher`` comparable to each other.

        It is safe to do so, as the subclasses do not possess more intrinsic
        information about the cipher than a ``Cipher`` would do; Merely the
        initialization process is different.
        """

        set_outputs = set([ax for ax in self.outputs if ax != Cipher.NOT_SET])
        arr = {
            (hash(a), hash(b)): tuple(
                sorted([xy for (ab, xy) in self.edges if ab == (a, b)])
            )
            for (a, b) in set(_ab for _ab, _ in self.edges)
        } | {
            (hash(self.nodes[a]), hash(self.OUT)): tuple(
                sorted([(x, y) for y, (_a, x) in enumerate(set_outputs) if _a == a])
            )
            for a, _ in set_outputs
        }
        return hash(tuple(arr.items()))

    def __repr__(self):
        r"""
        Method determining the output of ``print(self)``.
        """
        r = f"{self.name}: {self.input_length} -> {self.output_length} bits"
        if len(self.nodes) > 0:
            r += "\n    Sub ciphers:"
        for i, v in enumerate(self.nodes):
            if not isinstance(v, Cipher.__Special_Node):
                name = v.name if v.name is not None else "Unnamed cipher"
                l_in = v.input_length
                l_out = v.output_length
                r += f"\n    {i}: {name}: {l_in} -> {l_out} bits"
        return r

    def _latex_(self):
        r"""
        Generates LaTeX code for the cipher graph of ``self``.

        EXAMPLES::

            sage: from civerly.cipher_implementations.present import PRESENT_CVL
            sage: present = PRESENT_CVL(2)
            sage: latex(present)
            \documentclass{article}
            ...
            \end{document}
        """
        STRING = "\\documentclass{article}\n"
        STRING += "\\usepackage{tikz}\n\\usepackage[margin=2cm]{geometry}\n"
        STRING += "\\usetikzlibrary{arrows}\n"
        STRING += "\\usepackage{graphicx}\n"
        STRING += "\\usepackage{calc}\n"
        STRING += "\\newsavebox{\\tempbox}\n"
        STRING += "\\newlength{\\tempwidth}\n"
        STRING += "\\newlength{\\tempheight}\n"
        STRING += "\\newcommand{\\specialresizebox}[1]{\n"
        STRING += "\t\\sbox{\\tempbox}{#1}\n"
        STRING += "\t\\setlength{\\tempwidth}{\\wd\\tempbox}\n"
        STRING += "\\setlength{\\tempheight}{\\ht\\tempbox}\n"
        STRING += "\t\\ifdim\\tempwidth>\\tempheight\n"
        STRING += "\t\t\\resizebox{0.5\\textwidth}{!}{#1}\n"
        STRING += "\t\\else\n"
        STRING += "\t\t\\resizebox{!}{0.8\\textheight}{#1}%\n"
        STRING += "\t\\fi\n"
        STRING += "}\n"
        name = self.name.replace("_", "\\_")
        STRING += "\\title{Graph of \\texttt{" + name + "}}\n"
        STRING += "\\author{ }\n"
        STRING += "\\institute{\\texttt{cryptosolutions}}\n"
        STRING += "\\begin{document}\n"
        STRING += "\\maketitle\n"

        # recursively calls '._to_tikz()' of each component.
        STRING += self._to_tikz(_comps=[])

        STRING += "\\end{document}\n"
        return STRING

    def _to_tikz(self, _comps=[]):
        r"""
        Convert the graph of ``self`` to tikz code.

        EXAMPLES::

            sage: from civerly.cipher import Cipher
            sage: from civerly.component import SBox_CVL
            sage: from sage.crypto.sbox import SBox
            sage: cipher = Cipher(9, 9, name="Cipher")
            sage: sb = SBox_CVL(SBox([0, 6, 1, 4, 2, 3, 5, 7]))
            sage: edges = [(cipher.IN, (i, i)) for i in range(3)]
            sage: node_s0 = cipher.add_subcipher(sb, edges)
            sage: edges = [(cipher.IN, (i + 3, i)) for i in range(3)]
            sage: node_s1 = cipher.add_subcipher(sb, edges)
            sage: edges = [(cipher.IN, (i + 6, i)) for i in range(3)]
            sage: node_s2 = cipher.add_subcipher(sb, edges)
            sage: cipher.add_output([(node_s0, (i, i)) for i in range(3)])
            sage: cipher.add_output([(node_s1, (i, i + 3)) for i in range(3)])
            sage: cipher.add_output([(node_s2, (i, i + 6)) for i in range(3)])
            sage: print(cipher._to_tikz())
            \section{Graph of \texttt{Cipher} }
            \begin{center}
            \specialresizebox{
            \begin{tikzpicture}
                \node[circle,draw] at (1, 0) (node0) { \tiny \texttt{in} };
                \node[circle,draw] at (0, -2) (node1) { \tiny \texttt{ Unnamed Component } };
                \node[circle,draw] at (2, -2) (node2) { \tiny \texttt{ Unnamed Component } };
                \node[circle,draw] at (4, -2) (node3) { \tiny \texttt{ Unnamed Component } };
                \node[circle,draw] at (0, -4) (node4) { \tiny \texttt{ Cipher.OUT } };
                \node[circle,draw] at (1, -6) (out) { \tiny \texttt{out} };
                \draw[-latex] (node0) -- (node1) node[midway, above, sloped] {\tiny 3 };
                \draw[-latex] (node2) -- (node4) node[midway, above, sloped] {\tiny 3 };
                \draw[-latex] (node3) -- (node4) node[midway, above, sloped] {\tiny 3 };
                \draw[-latex] (node0) -- (node3) node[midway, above, sloped] {\tiny 3 };
                \draw[-latex] (node1) -- (node4) node[midway, above, sloped] {\tiny 3 };
                \draw[-latex] (node0) -- (node2) node[midway, above, sloped] {\tiny 3 };
                \draw[-latex] (node1) -- (out) node[midway, above, sloped] {\tiny 3 };
                \draw[-latex] (node2) -- (out) node[midway, above, sloped] {\tiny 3 };
                \draw[-latex] (node3) -- (out) node[midway, above, sloped] {\tiny 3 };
                \end{tikzpicture}
            }
            \end{center}
            <BLANKLINE>
            <BLANKLINE>
        """
        depths = self._dfs_traversal()

        STRING = ""
        name = self.name.replace("_", "\\_")
        STRING += "\\section{Graph of \\texttt{" + name + "} }\n"
        STRING += "\\begin{center}\n"
        STRING += "\\specialresizebox{\n"
        STRING += "\\begin{tikzpicture}\n"

        maximal_count = max([depths.count(i) for i in depths])

        ctr = dict.fromkeys(set(depths), 0)
        # Draw each node
        for i in range(len(self.nodes)):
            if i == 0:
                STRING += f"\t\\node[circle,draw] at ({maximal_count // 2}, 0) "
                STRING += f"(node{i}) {{ \\tiny \\texttt{{in}} }};\n"
            else:
                STRING += "\t\\node[circle,draw] at "
                STRING += f"({2 * ctr[depths[i]]}, {-2 * depths[i]}) (node{i}) "
                name = self.nodes[i].name.replace("_", "\\_")
                STRING += f"{{ \\tiny \\texttt{{ {name} }} }};\n"
            ctr[depths[i]] += 1
        STRING += "\t\\node[circle,draw] at "
        STRING += f"({maximal_count // 2}, {-2 * depths[i] - 2}) (out) "
        STRING += "{ \\tiny \\texttt{out} };\n"

        without_index_list = [ab for ab, xy in self.edges]
        # draw the edges on a component wise level
        for a, b in set(without_index_list):
            if type(a) is int:
                STRING += f"\t\\draw[-latex] (node{a}) -- (node{b}) "
                k = without_index_list.count((a, b))
                STRING += f"node[midway, above, sloped] {{\\tiny {k} }};\n"
            else:
                STRING += f"\t\\draw[-latex] (node{0}) -- (node{b}) "
                k = without_index_list.count((a, b))
                STRING += f"node[midway, above, sloped] {{\\tiny {k} }};\n"

        without_index_out = [a for c, (a, b) in enumerate(self.outputs)]
        # draw the output edges on a component wise level
        for a in set(without_index_out):
            if type(a) is int:
                STRING += f"\t\\draw[-latex] (node{a}) -- (out) "
                k = without_index_out.count(a)
                STRING += f"node[midway, above, sloped] {{\\tiny {k} }};\n"
            else:
                STRING += f"\t\\draw[-latex] (node{0}) -- (out) "
                k = without_index_out.count(a)
                STRING += f"node[midway, above, sloped] {{\\tiny {k} }};\n"

        STRING += "\t\\end{tikzpicture}\n"
        STRING += "}\n"
        STRING += "\\end{center}\n\n"

        # recursively iterate through the subciphers
        for i, subcipher in enumerate(self.nodes):
            if i > 0:
                # To avoid redundancy of displaying the components
                if subcipher not in _comps:
                    STRING += subcipher._to_tikz(_comps=_comps)
                    _comps.append(subcipher)

        return STRING

    def _dfs_traversal_help(self, node, visited, order, depths, current_depth):
        """
        Helper function for ``self._dfs_traversal``, which performs the main
        recursion steps.
        """
        if depths[node] < current_depth:
            if visited[node]:
                # If this node has been visited before,
                order.remove(node)
            order.append(node)  # move it to the end of our DFS-order
            depths[node] = current_depth  # and overwrite its depth
            visited[node] = True  # as well as its visited status
            for b in [b for (a, b), _ in self.edges if node == a]:
                # if not visited[b]: # reiterate over already visited nodes to
                # get the maximum depth
                self._dfs_traversal_help(b, visited, order, depths, current_depth + 1)

    def _dfs_traversal(self):
        """
        Performs a dfs search through the cipher DAG, in order to determine the
        ``dfs_order`` and an array of the ``depths`` of each visited component.

        INPUT:: None

        OUTPUT::

            - ``depths`` -- optional; A list containing the depths of each
              component, which is indexed by the DFS-ordering of the components

            - ``dfs_order`` -- The DFS-ordering indexed by the indices from
              ``self.nodes``

        TESTS::

            sage: from sage.crypto.sboxes import PRESENT
            sage: from civerly.cipher import Cipher
            sage: from civerly.component import SBox_CVL
            sage: cipher = Cipher(32, 32, name="doctest-cipher")
            sage: S = SBox_CVL(PRESENT, name="S")
            sage: for j in range(4):
            ....:     edges = [(cipher.IN, ((i + 4*j + 3) % 16, i)) for i in range(4)]
            ....:     node = cipher.add_subcipher(S, edges)
            ....:     edges = [(node, (i, i)) for i in range(4)]
            ....:     node = cipher.add_subcipher(S, edges)
            ....:     edges = [(node, (i, i + 4*j)) for i in range(4)]
            ....:     cipher.add_output(edges)
            sage: for j in range(4, 8):
            ....:     edges = [(cipher.IN, (i + 4*j, i)) for i in range(4)]
            ....:     node = cipher.add_subcipher(S, edges)
            ....:     edges = [(node, (i, i + 4*j)) for i in range(4)]
            ....:     cipher.add_output(edges)
            sage: cipher._dfs_traversal()
            [0, 1, 2, 1, 2, 1, 2, 1, 2, 1, 1, 1, 1, 3]
        """
        if not self.is_valid:
            raise CipherNotValidException()
        visited = [False for _ in range(len(self.nodes))]
        dfs_order = []
        depths = [-1 for _ in range(len(self.nodes))]

        self._dfs_traversal_help(
            self.nodes.index(self.IN), visited, dfs_order, depths, 0
        )

        # handle components like ``C_CVL`` that are unreachable using
        # conventional DFS-search
        for (a, b), (x, y) in self.edges:
            if not visited[a] and visited[b]:
                depths[a] = depths[b] - 1
                visited[a] = True
                dfs_order.append(a)

        e = (
            f"{self.name}.OUT doesn't have the highest depth "
            f"({depths[self.nodes.index(self.OUT)]}, max is "
            f"{max(depths)} by {self.nodes[depths.index(max(depths))]})!"
        )
        assert depths[self.nodes.index(self.OUT)] == max(depths), e

        return depths

    def model(self, model_options, _first_iter=True):
        """
        Generate the model for ``self`` according to the given
        ``model_options``. Calls one of the two modeling methods
        :meth:`self._model_milp` or :meth:`self._model_sat`, depending on the
        chosen optimization mode in ``model_options``.

        INPUT:

            - ``model_options`` -- see
              :class:`civerly.model_options.MODEL_OPTIONS`

        OUTPUT:

            - the generated model
        """
        start_time = time.perf_counter()
        if model_options.optimization == OPTIMIZATION.MILP:
            self._model = self._model_milp(model_options, _first_iter=_first_iter)
            self._model_time = time.perf_counter() - start_time
            return self._model
        elif model_options.optimization == OPTIMIZATION.SAT:
            self._model = self._model_sat(model_options, _first_iter=_first_iter)
            self._model_time = time.perf_counter() - start_time
            return self._model
        else:
            raise InvalidModelOptionException(model_options.optimization, OPTIMIZATION)

    def _model_milp(self, model_options, _first_iter=False):
        e = f"MILP modeling is not supported for {type(self)}!"
        raise NotImplementedError(e)

    def _model_sat(self, model_options, _first_iter=False):
        r"""
        Generate the SAT-model for ``self`` according to the given
        ``model_options``.

        INPUT:

            - ``model_options`` -- see
              :class:`civerly.model_options.MODEL_OPTIONS`

        We first generate a ``master_sat``, recursively iterate over
        ``self.nodes`` (and its subciphers) and collect the sub-SATs in
        order to relabel and connect them correctly to one big SAT formula. To
        avoid redundancy, a caching-mechanism is implemented which checks if
        the currently modeled component was modeled before. If yes, the SAT
        will be copied over instead of being generated from scratch again.

        .. WARNING::

            Convention: SAT_IN, SAT_OUT occupy the first indices!
        """
        assert isinstance(_first_iter, bool)
        if model_options.granularity == GRANULARITY.WORDWISE:
            raise InvalidModelOptionException(
                model_options.granularity,
                message="Wordwise modeling is not supported for SAT!",
            )

        # create the directory models are written to
        if model_options.write_to_file:
            model_options.path.mkdir(parents=True, exist_ok=True)

        # do not write the sub models to file
        model_options_ = replace(model_options, write_to_file=False)
        model_options, model_options_ = model_options_, model_options

        # flag to stop when a model needs to be solved externally
        self._return_immediately_ = False

        # ------------------------------------------------------------------------
        cnf_file_name = model_options.path / (f"{self.name.replace(' ', '_')}.cnf")
        if model_options.path is not None:
            master_sat = DIMACS(filename=cnf_file_name)
        else:
            master_sat = DIMACS()
        self.SAT_IN = [master_sat.var() for _ in range(self.input_length)]
        self.SAT_OUT = [master_sat.var() for _ in range(self.output_length)]

        sats = []
        self.sum_arr_sat = []
        # ------------------------------------------------------------------------

        # dictionaries for translating variables in sage and the mps file
        self.dictionaries_sat = [{} for _ in range(len(self.nodes))]
        self.inv_dictionaries_sat = [{} for _ in range(len(self.nodes))]

        for i_comp, comp in enumerate(self.nodes):
            # check if component was modeled before
            for i_prev, prev in enumerate(self.nodes[:i_comp]):
                if comp == prev:
                    # copy over attributes related to modeling
                    comp.sat = prev.sat
                    comp.SAT_IN = prev.SAT_IN
                    comp.SAT_OUT = prev.SAT_OUT
                    comp.sum_arr_sat = prev.sum_arr_sat

                    # copy the component sat programs
                    sats.append(comp.sat)

                    # copy the dictionaries
                    self.dictionaries_sat[i_comp] = {
                        master_sat.var(): val
                        for _, val in sorted(
                            self.dictionaries_sat[i_prev].items(),
                            key=lambda _tup: _tup[0],
                        )
                    }
                    self.inv_dictionaries_sat[i_comp] = {
                        v: k for k, v in self.dictionaries_sat[i_comp].items()
                    }

                    # recursively copy component dictionaries
                    comp._copy_over_dictionaries_recursively(prev, model_options)
                    # copy the objective variables
                    self.sum_arr_sat += [
                        (factor, self.inv_dictionaries_sat[i_comp][entry])
                        for factor, entry in prev.sum_arr_sat
                    ]

                    for asg in sats[i_comp].clauses():
                        # copy the (translated) clauses
                        clause = []
                        for variable in asg[0]:
                            assert variable != 0, (
                                "During translation, a variable appears tohave value 0!"
                            )
                            clause.append(
                                (-1) ** (variable < 0)
                                * self.inv_dictionaries_sat[i_comp][abs(variable)]
                            )
                        master_sat.add_clause(tuple(clause))
                    break
            else:
                # model the components that have not been modeled before
                comp_sat = comp.model(model_options, _first_iter=False)
                sats.append(comp_sat)

                # if we need to return immediately,
                # (because a model must be solved externally)
                # pass this up the program flow
                if comp._return_immediately_:
                    comp._return_immediately_ = False
                    self._return_immediately_ = True
                    return

                ##############################################################
                # parse the component SAT and adopt it into the master sat   #
                ##############################################################
                for variable in range(1, comp_sat.nvars() + 1):
                    new_index = master_sat.var()
                    self.dictionaries_sat[i_comp][new_index] = variable
                self.inv_dictionaries_sat[i_comp] = {
                    v: k for k, v in self.dictionaries_sat[i_comp].items()
                }

                for asg in comp_sat.clauses():
                    # copy the (translated) clauses
                    clause = []
                    for variable in asg[0]:
                        assert variable != 0, (
                            "During translation, a variable appears tohave value 0!"
                        )
                        clause.append(
                            (-1) ** (variable < 0)
                            * self.inv_dictionaries_sat[i_comp][abs(variable)]
                        )
                    master_sat.add_clause(tuple(clause))

                # copy over sum_arr_sat
                self.sum_arr_sat += [
                    (factor, self.inv_dictionaries_sat[i_comp][entry])
                    for factor, entry in comp.sum_arr_sat
                ]

        # Connect the SATs with each other
        # --------------- set SAT_IN and SAT_OUT variables ---------------- #
        for i_comp, comp in enumerate(self.nodes):
            if comp == self.IN:
                for x in range(comp.input_length):
                    master_sat.add_clause(
                        (self.SAT_IN[x], -self.inv_dictionaries_sat[i_comp][x + 1])
                    )
                    master_sat.add_clause(
                        (-self.SAT_IN[x], self.inv_dictionaries_sat[i_comp][x + 1])
                    )
            elif comp == self.OUT:
                for x in range(comp.output_length):
                    master_sat.add_clause(
                        (
                            self.inv_dictionaries_sat[i_comp][
                                x + 1 + comp.input_length
                            ],
                            -self.SAT_OUT[x],
                        )
                    )
                    master_sat.add_clause(
                        (
                            -self.inv_dictionaries_sat[i_comp][
                                x + 1 + comp.input_length
                            ],
                            self.SAT_OUT[x],
                        )
                    )

        # -------------- Find comp.IN/OUT and connect these -------------- #
        # dictionary of branches with key in_node and value [out_node0,
        # out_node1, ...]
        branches = dict()
        # take the edges in the graph to combine the SATs
        for (a, b), (x, y) in self.edges:
            bINy = self.inv_dictionaries_sat[b][y + 1]
            aOUTx = self.inv_dictionaries_sat[a][x + 1 + self.nodes[a].input_length]
            if aOUTx not in branches:
                branches[aOUTx] = []
            branches[aOUTx].append(bINy)

        # Implement branching
        for in_node, out_nodes in branches.items():
            assert len(out_nodes) > 0, f"Component {in_node} needs to have an output!"

            if model_options.cryptanalysis == CRYPTANALYSIS.DIFFERENTIAL:
                # All output branches receive the difference of the input
                # branch
                for out_node in out_nodes:
                    master_sat.add_clause((-in_node, out_node))
                    master_sat.add_clause((in_node, -out_node))

            elif model_options.cryptanalysis == CRYPTANALYSIS.LINEAR:
                from sage.matrix.constructor import Matrix as matrix

                from civerly.component import LinearLayer_CVL
                from civerly.model_options import LINEAR_LAYER_MODELING, MODEL_OPTIONS

                # Linear model of n-branching == Differential model of n-XOR
                mat = matrix([1] * len(out_nodes))

                branching = LinearLayer_CVL(mat)
                branching_sat = branching._model_sat(
                    MODEL_OPTIONS(
                        cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
                        optimization=OPTIMIZATION.SAT,
                        linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
                        granularity=GRANULARITY.BITWISE,
                    )
                )
                branching_nodes = out_nodes + [in_node]
                # copy over the clauses generated by ``LinearLayer_CVL``
                for clause in branching_sat.clauses():
                    master_sat.add_clause(
                        translate_sat_clause(branching_nodes, clause[0])
                    )

        # set all "dangling" nodes to zero (especially
        # important for linear cryptanalysis)
        edge_arr = [(a, x) for (a, b), (x, y) in self.edges]
        for a in range(len(self.nodes)):
            for x in range(self.nodes[a].output_length):
                if (a, x) not in edge_arr + self.outputs:
                    if (
                        isinstance(self.nodes[a], Cipher.__Special_Node)
                        and not self.nodes[a].in_node
                    ):
                        pass  # skip OUT-nodes
                    else:
                        master_sat.add_clause((-self.inv_dictionaries_sat[a][x + 1],))

        model_options, model_options_ = model_options_, model_options

        return self._finish_sat(model_options, master_sat, _first_iter=_first_iter)

    def _finish_sat(self, model_options, sat, _first_iter=False):
        r"""
        Finalizes the constructed SAT model, by firstly adding a clause that
        excludes the all-zero trail, and secondly by encoding a fixed
        probability for potential trails. If there exists no trail with the
        given probability, then the CNF model is UNSAT, if there exists at
        least one such trail, then it is SAT.
        """
        assert isinstance(sat, DIMACS)
        assert isinstance(_first_iter, bool)
        # store the sum_arr_sat into a ``.json`` file to be able to retrieve it
        # later on
        file_name = model_options.path / self.name.replace(" ", "_")
        with open(f"{file_name}sum.json", "w") as f:
            json.dump(self.sum_arr_sat, f)
            f.close()

        # Save the dictionary files as json
        with open(model_options.path / (self.name + "_d.json"), "w") as f:
            json.dump(self.dictionaries_sat, f)
            f.close()

        with open(model_options.path / (self.name + "_id.json"), "w") as f:
            json.dump(self.inv_dictionaries_sat, f)
            f.close()

        if _first_iter:
            # At least one variable that does not belong to PROB needs to be
            # active
            tup = tuple(
                var
                for var in range(1, sat.nvars() + 1)
                if var not in [entry for _, entry in self.sum_arr_sat]
            )
            sat.add_clause(tup)

        if model_options.write_to_file:
            sat.write()
            print(
                f"{sat.nvars()} variables and {len(sat.clauses())} clauses "
                "were written to "
                f"'{str(model_options.path / (self.name + '.cnf'))}'"
            )

        self.sat = sat
        return sat

    def analyse(self, model_options):
        """
        Analyse this cipher. That is, generate the model, solve it and return
        the result.

        INPUT:

            - ``model_options`` -- see
              :class:`civerly.model_options.MODEL_OPTIONS`

        When ``model_options.number_of_solutions == 1`` (the default), a
        single optimal trail is found and its weight is returned.
        When ``number_of_solutions > 1``, the solver looks for that many
        distinct solutions; the method returns a **list** of that many optimal
        weights (one per solution found), sorted in ascending order.
        Furthermore, all trails are available in ``self.results``
        (list of ``{"in": ..., "out": ..., "weight": ...}`` dicts).

        .. WARNING::

            Requires the specified solver to be installed.
        """
        start_time_analyse = time.perf_counter()
        # Reset per-analysis state.
        self.results = []
        self.trail_nodes = []

        if model_options.optimization == OPTIMIZATION.MILP:
            if self.milp is None:
                self.model(model_options)
            else:
                print("Using existing MILP model, make sure it is up to date!")
                self._finish_milp(model_options, self.milp)
            input_file = model_options.path / (self.name + ".mps")
            if model_options.number_of_solutions > 1:
                # Trail vars are the per-node X<i>[j] columns; IN/OUT and any
                # helper/dummy variables are excluded so that two solutions
                # are considered the same when they agree on the trail.
                b = self.milp.get_backend()
                trail_vars = {
                    b.col_name(i)
                    for i in range(b.ncols())
                    if b.col_name(i).startswith("X")
                }
                all_results = model_options.milp_solver.solve_multiple(
                    input_file=input_file,
                    milp=self.milp,
                    number_of_solutions=model_options.number_of_solutions,
                    trail_vars=trail_vars,
                )
                self._solve_time = 0
                weights = []
                for r in all_results:
                    self._solve_time = self._solve_time + r["solve_time"]
                    if r["objective_value"] is None:
                        continue
                    TrailNode(
                        self,
                        model_options,
                        (r["assignment"], r["objective_value"]),
                    )
                    weights.append(r["objective_value"])
                self._analyse_time = time.perf_counter() - start_time_analyse
                return weights
            else:
                self.result = model_options.milp_solver.solve(input_file)
                self._solve_time = self.result["solve_time"]
                results_and_weight = (
                    self.result["assignment"],
                    self.result["objective_value"],
                )
                TrailNode(self, model_options, results_and_weight)
                self._analyse_time = time.perf_counter() - start_time_analyse
                return self.result["objective_value"]
        elif model_options.optimization == OPTIMIZATION.SAT:
            if self.sat is None:
                self.model(model_options)
            else:
                print("Using existing SAT model, make sure it is up to date!")
                self._finish_sat(model_options, self.sat)
            if self._return_immediately_:
                return
            input_file = model_options.path / (self.name + ".cnf")
            sum_arr_file = model_options.path / (self.name + "sum.json")
            if model_options.number_of_solutions > 1:
                start_time = time.perf_counter()
                # Trail vars: the sum_arr variables (which encode the weight)
                # plus the input variables. Helper/auxiliary clauses (e.g.
                # the sum-counter aux vars) are excluded so that two
                # solutions are considered the same when they agree on the
                # trail.
                with open(sum_arr_file) as f:
                    sum_arr = json.load(f)
                trail_vars = {int(var) for _, var in sum_arr} | set(
                    range(1, self.input_length + 1)
                )
                all_results = model_options.sat_solver.solve_multiple(
                    input_file=input_file,
                    sum_arr_file=sum_arr_file,
                    solve_range=model_options.solve_range,
                    number_of_solutions=model_options.number_of_solutions,
                    trail_vars=trail_vars,
                    precision=model_options.sat_precision,
                )
                self._solve_time = 0
                weights = []
                for r in all_results:
                    self._solve_time = self._solve_time + r["solve_time"]
                    if r["objective_value"] is None:
                        continue
                    TrailNode(
                        self,
                        model_options,
                        (r["assignment"], r["objective_value"]),
                    )
                    weights.append(r["objective_value"])
                self._analyse_time = time.perf_counter() - start_time_analyse
                return weights
            else:
                # if no sat_solver has been selected, we generate all cnf-files
                # for the given solve_range
                self.result = model_options.sat_solver.solve(
                    input_file,
                    sum_arr_file=sum_arr_file,
                    solve_range=model_options.solve_range,
                    precision=model_options.sat_precision,
                )
                self._solve_time = self.result["solve_time"]
                results_and_weight = (
                    self.result["assignment"],
                    self.result["objective_value"],
                )
                TrailNode(self, model_options, results_and_weight)
                self._analyse_time = time.perf_counter() - start_time_analyse
                return self.result["objective_value"]
        else:
            raise InvalidModelOptionException(model_options.optimization, OPTIMIZATION)

    def _construct_grid(self, divide_by, input_side=True):
        r"""
        In order to introduce some structure into the cipher (which initially
        is just a DAG), we construct a grid of all components based on their
        depth, which is assigned via dfs-search.

         This grid is used in the report generation, in order to draw
        components with the same depth on the same report layer. Furthermore,
        the flag ``input_side`` determines the position at which the nodes are
        drawn in each layer, namely either the input or output side.

         INPUT:

             - ``divide_by`` -- int; the word size by which we divide by when
               displaying nibbles.

             - ``input_side`` -- bool; indicates whether grid shows the input
               (``True``) or output side (``False``)
        """
        depths = self._dfs_traversal()

        # initialize grid
        grid_in = []
        grid_out = []

        for depth in range(max(depths) + 1):
            width_in = sum(
                self.nodes[w].input_length // divide_by
                for w in range(len(self.nodes))
                if depths[w] == depth
            )
            width_out = sum(
                self.nodes[w].output_length // divide_by
                for w in range(len(self.nodes))
                if depths[w] == depth
            )
            grid_in.append([None for _ in range(width_in)])
            grid_out.append([None for _ in range(width_out)])

        for i in range(self.IN.input_length // divide_by):
            grid_in[0][i] = (self.nodes.index(self.IN), i)
        for i in range(self.IN.output_length // divide_by):
            grid_out[0][i] = (self.nodes.index(self.IN), i)

        offset_in = [self.IN.input_length] + [0 for _ in range(max(depths))]
        offset_out = [0 for _ in range(max(depths) + 1)]
        visited = [True] + [False for _ in range(1, len(self.nodes))]

        # fill the grid
        for depth in range(max(depths) + 1):
            # grid_out -> grid_in, following along the edges
            # ----------------------------------------

            # edges on current layer sorted by b
            sorted_edges_depth = sorted(
                [
                    ((a, b), (x, y))
                    for (a, b), (x, y) in self.edges
                    if depths[b] == depth
                ],
                key=lambda _inp: _inp[0][1],
            )

            for ctr, ((a, b), (x, y)) in enumerate(sorted_edges_depth):
                # if we find a new component (i.e. we finished the previous one
                # because we sorted the edges)
                if b not in [e[0][1] for e in sorted_edges_depth[:ctr]]:
                    offset_in[depth] += self.nodes[b].input_length

                grid_index = (
                    offset_in[depth] - self.nodes[b].input_length + y
                ) // divide_by
                grid_in[depth][grid_index] = (b, y // divide_by)
                visited[b] = True

            # grid_in -> grid_out, preserving order in the current layer
            # ----------------------------------------------------------
            for ctr, (b, y) in enumerate(grid_in[depth]):
                if b not in [b for (b, _) in grid_in[depth][:ctr]]:
                    for b_bit in range(self.nodes[b].output_length // divide_by):
                        grid_out[depth][offset_out[depth]] = (b, b_bit)
                        offset_out[depth] += 1

        # Go backwards to find unreachable nodes (e.g. C_CVL) too
        remaining_nodes = [node for node in range(len(self.nodes)) if not visited[node]]
        # ----------------------------------------------------------
        for node in remaining_nodes:
            depth = depths[node]
            for x in range(self.nodes[node].input_length):
                grid_index = (offset_in[depth] + x) // divide_by
                grid_in[depths[node]][grid_index] = (node, x // divide_by)
            offset_in[depth] += self.nodes[node].input_length

            for y in range(self.nodes[node].output_length):
                grid_index = (offset_out[depth] + y) // divide_by
                grid_out[depths[node]][grid_index] = (node, y // divide_by)
            offset_out[depth] += self.nodes[node].output_length

        if input_side:
            return grid_in
        else:
            return grid_out

    def _from_grid(self, node_num, current_index, model_options, input_side=True):
        r"""
        Recovers ``(node_num, current_index)`` from grid.
        """
        if model_options.granularity == GRANULARITY.WORDWISE:
            divide_by = self.wordsize
        elif model_options.granularity == GRANULARITY.BITWISE:
            divide_by = 1
        grid = self._construct_grid(divide_by=divide_by, input_side=input_side)

        for grid_row in grid:
            if (node_num, current_index) in grid_row:
                return grid_row.index((node_num, current_index))

        # ------------------------ if nothing was found
        raise AssertionError(
            f"{(self.nodes[node_num].name, node_num)}[{current_index}] "
            "is not found in grid!"
        )

    def read_results(self, model_options):
        r"""
        Re-read the most recent solution from disk and return
        ``(assignment, objective_value)`` -- the shape :class:`TrailNode`
        expects.

        Used by :meth:`generate_report` and :meth:`get_trail` to reconstruct
        a trail in a fresh session, without re-running :meth:`analyse`.

        .. NOTE::

            The SAT path is not currently functional: the new
            :meth:`SAT_SOLVER_CVL.solve` does not persist the optimum to a
            canonical ``.sat`` file, and the per-iteration files don't carry
            the weight. To re-read a SAT result, call :meth:`analyse` again.
        """
        if hasattr(self, "result"):
            return self.result["assignment"], self.result["objective_value"]
        if model_options.optimization == OPTIMIZATION.MILP:
            solution_file = model_options.path / (self.name + ".sol")
            objective_value, assignment = (
                model_options.milp_solver._process_solution_file(solution_file)
            )
            return (assignment, objective_value)
        elif model_options.optimization == OPTIMIZATION.SAT:
            raise NotImplementedError
        else:
            raise InvalidModelOptionException(model_options.optimization, OPTIMIZATION)

    def generate_report(self, model_options):
        """
        Generates a ``.tex`` file that contains the state matrices of active
        words after each component, and compiles it to a PDF.

        INPUT:

            - ``model_options`` -- see
              :class:`civerly.model_options.MODEL_OPTIONS`

        OUTPUT: None, but writes one or more PDF files.

        When ``model_options.number_of_solutions == 1`` (default) a single
        ``<name>.pdf`` is produced (existing behaviour).

        When ``model_options.number_of_solutions > 1``, one PDF per solution
        is produced, named ``<name>_sol0.pdf``, ``<name>_sol1.pdf``, ...
        The stored :attr:`trail_nodes` (populated by the preceding
        :meth:`analyse` call) are used directly; no solution files are
        re-read.
        """

        if model_options.number_of_solutions == 1:
            # ---- single-solution path (unchanged) --------------------------
            # 1. Get results
            results_and_weight = self.read_results(model_options)
            # 2. Construct TrailNode
            root_node = TrailNode(self, model_options, results_and_weight)
            # 3. Verify correctness
            root_node.verify_correctness()
            # 4. Generate LaTeX string
            string = self._latex_header(model_options, results_and_weight[1])
            string += root_node.to_latex(model_options)
            string += "\\end{document}\n"
            # 5. Write to .tex file and compile to pdf
            self._write_and_compile_tex(string, model_options)
        else:
            # ---- multi-solution path ---------------------------------------
            if not self.trail_nodes:
                raise RuntimeError(
                    "generate_report() with number_of_solutions > 1 requires "
                    "analyse() to have been called first with the same "
                    "model_options."
                )
            for i, (tn, sol) in enumerate(zip(self.trail_nodes, self.results)):
                # 3. Verify correctness
                tn.verify_correctness()
                # 4. Generate LaTeX string
                string = self._latex_header(model_options, sol["weight"])
                string += tn.to_latex(model_options)
                string += "\\end{document}\n"
                # 5. Write to .tex file and compile to pdf
                self._write_and_compile_tex(
                    string, model_options, _stem=f"{self.name}_sol{i}"
                )

    def get_trail(self, model_options):
        r"""
        After solving a MILP or SAT, converts the solution values to a
        trail-like output as a ``TrailNode`` tree.  Similar to
        :meth:`generate_report`, but returns the tree instead of a PDF.

        When ``model_options.number_of_solutions == 1`` (default), a single
        :class:`civerly.trail.TrailNode` is returned (existing behaviour).

        When ``model_options.number_of_solutions > 1``, a **list** of
        :class:`civerly.trail.TrailNode` objects is returned (one per
        solution, best first).  The stored :attr:`trail_nodes` (populated by
        the preceding :meth:`analyse` call) are returned directly.
        """

        if model_options.number_of_solutions == 1:
            results_and_weight = (
                self.result["assignment"],
                self.result["objective_value"],
            )
            root_node = TrailNode(self, model_options, results_and_weight)
            root_node.verify_correctness()
            return root_node
        else:
            if not self.trail_nodes:
                raise RuntimeError(
                    "get_trail() with number_of_solutions > 1 requires "
                    "analyse() to have been called first with the same "
                    "model_options."
                )
            for tn in self.trail_nodes:
                tn.verify_correctness()
            return list(self.trail_nodes)

    def _to_dict(self):
        r"""
        Return a JSON-serializable dictionary representation of ``self``.

        Used internally by :meth:`export` and :meth:`load`.
        """
        out_idx = len(self.nodes) - 1 if self.is_valid else None

        node_dicts = [
            {**n._to_dict(), "results": n.results}
            for i, n in enumerate(self.nodes)
            if out_idx is None or i != out_idx
        ]

        edge_dicts = [
            ((a, b), (x, y))
            for (a, b), (x, y) in self.edges
            if out_idx is None or b != out_idx
        ]

        output_dicts = [
            list(entry) if entry is not None else None for entry in self.outputs
        ]

        return {
            "type": "Cipher",
            "name": self.name,
            "input_length": self.input_length,
            "output_length": self.output_length,
            "nodes": node_dicts,
            "edges": edge_dicts,
            "outputs": output_dicts,
            "results": self.results,
        }

    def export(self, path):
        r"""
        Write ``self`` to a JSON file at ``path``.

        The file can be loaded back with :meth:`Cipher.load`.

        INPUT:

            - ``path`` -- string or path-like; Destination file path.
              The ``.json`` extension is conventional but not enforced.

        EXAMPLES::

            sage: import tempfile, os
            sage: from civerly.cipher import Cipher
            sage: from civerly.component import SBox_CVL
            sage: from sage.crypto.sbox import SBox
            sage: cipher = Cipher(9, 9, name="test")
            sage: sb = SBox_CVL(SBox([0, 6, 1, 4, 2, 3, 5, 7]))
            sage: edges = [(cipher.IN, (i, i)) for i in range(3)]
            sage: node0 = cipher.add_subcipher(sb, edges)
            sage: edges = [(cipher.IN, (i + 3, i)) for i in range(3)]
            sage: node1 = cipher.add_subcipher(sb, edges)
            sage: edges = [(cipher.IN, (i + 6, i)) for i in range(3)]
            sage: node2 = cipher.add_subcipher(sb, edges)
            sage: cipher.add_output([(node0, (i, i)) for i in range(3)])
            sage: cipher.add_output([(node1, (i, i + 3)) for i in range(3)])
            sage: cipher.add_output([(node2, (i, i + 6)) for i in range(3)])
            sage: with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            ....:     tmp = f.name

        Before analysis, ``results`` is ``[]`` and round-trips as such::

            sage: cipher.export(tmp)
            Object 'test' has been exported to ...
            sage: loaded = Cipher.load(tmp)
            sage: cipher == loaded and loaded.results == []
            True

        After analysis, ``results`` holds the trail bit-patterns and is
        preserved verbatim through the JSON file::

            sage: # optional - cadical, espresso
            sage: from civerly.model_options import *
            sage: model_options = MODEL_OPTIONS(
            ....:   cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:   optimization=OPTIMIZATION.SAT,
            ....:   granularity=GRANULARITY.BITWISE,
            ....:   linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:   sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:   sat_solver=SOLVER.CADICAL,
            ....:   logic_minimizer=SOLVER.ESPRESSO,
            ....:   path=Path("DOCTEST-Export"))
            sage: cipher.analyse(model_options)
            ...
            2
            sage: cipher.export(tmp)
            Object 'test' has been exported to ...
            sage: loaded = Cipher.load(tmp)
            sage: os.unlink(tmp)
            sage: cipher == loaded and loaded.results == cipher.results
            True

        Again with a different cipher type::
            sage: import tempfile
            sage: from civerly.cipher import Cipher
            sage: from civerly.cipher_implementations.aes import AES_CVL
            sage: aes = AES_CVL(4)
            sage: with tempfile.NamedTemporaryFile(suffix='.json') as f:
            ....:   tmp = f.name
            ....:   aes.export(tmp)
            ....:   loaded = Cipher.load(tmp)
            ....:   aes == loaded
            Object 'AES' has been exported to ...
            True

        """
        with open(path, "w") as f:
            json.dump(self._to_dict(), f, default=lambda obj: int(obj))
        print(f"Object '{self.name}' has been exported to {path}.")

    @classmethod
    def _init_from_dict(cls, d):
        r"""
        Construct a new empty cipher shell from a dictionary produced by
        :meth:`_to_dict`. Override in subclasses that have a different
        constructor signature.
        """
        return cls(d["input_length"], d["output_length"], name=d["name"])

    @staticmethod
    def _populate_from_dict(cipher, d):
        r"""
        Restore nodes, edges, outputs and results onto an empty cipher shell
        using data from a dictionary produced by :meth:`_to_dict`.
        """
        from civerly.addrx import AddRX
        from civerly.aeslike import AESlike
        from civerly.andrx import AndRX
        from civerly.component import (
            AND_CVL,
            C_CVL,
            I_CVL,
            RK_CVL,
            ROT_AND_CVL,
            XOR_CVL,
            ConstXOR_CVL,
            LinearLayer_CVL,
            ModAdd_CVL,
            PermuteLayer_CVL,
            RotateLayer_CVL,
            RoundkeyXOR_CVL,
            SBox_CVL,
        )
        from civerly.sboxcipher import SBoxCipher
        from civerly.wordbasedcipher import WordBasedCipher
        from civerly.wordsboxcipher import WordSBoxCipher

        _TYPE_MAP = {
            "Cipher": Cipher,
            "SBoxCipher": SBoxCipher,
            "WordBasedCipher": WordBasedCipher,
            "WordSBoxCipher": WordSBoxCipher,
            "AESlike": AESlike,
            "AddRX": AddRX,
            "AndRX": AndRX,
            "I_CVL": I_CVL,
            "C_CVL": C_CVL,
            "RK_CVL": RK_CVL,
            "ConstXOR_CVL": ConstXOR_CVL,
            "RoundkeyXOR_CVL": RoundkeyXOR_CVL,
            "XOR_CVL": XOR_CVL,
            "ModAdd_CVL": ModAdd_CVL,
            "AND_CVL": AND_CVL,
            "LinearLayer_CVL": LinearLayer_CVL,
            "PermuteLayer_CVL": PermuteLayer_CVL,
            "RotateLayer_CVL": RotateLayer_CVL,
            "SBox_CVL": SBox_CVL,
            "ROT_AND_CVL": ROT_AND_CVL,
        }

        def node_from_dict(nd):
            class_var = _TYPE_MAP[nd["type"]]
            if class_var is None:
                raise ValueError(f"Unknown node type {nd['type']!r} in JSON")
            return class_var._from_dict(nd)

        # Restore the IN node's result (index 0)
        cipher.nodes[0].results = d["nodes"][0]["results"]
        w = 1 if type(cipher) == Cipher else cipher.wordsize

        for node_idx, nd in enumerate(d["nodes"][1:], start=1):
            component = node_from_dict(nd)
            incoming = list(
                set(
                    [
                        (a, (x // w, y // w))
                        for (a, b), (x, y) in d["edges"]
                        if b == node_idx
                    ]
                )
            )
            cipher.add_subcipher(component, incoming)
            if not isinstance(component, Cipher):
                cipher.nodes[node_idx].results = nd["results"]

        output_edges = list(
            set(
                [
                    (a, (x // w, y // w))
                    for y, entry in enumerate(d["outputs"])
                    if entry is not None
                    for a, x in [entry]
                ]
            )
        )
        if output_edges:
            cipher.add_output(output_edges)

        cipher.results = d["results"]

    @classmethod
    def _from_dict(cls, d):
        r"""
        Reconstruct a :class:`Cipher` from a dictionary produced by
        :meth:`_to_dict`.
        """
        cipher = cls._init_from_dict(d)
        Cipher._populate_from_dict(cipher, d)
        return cipher

    @classmethod
    def load(cls, path):
        r"""
        Load and return a :class:`Cipher` from the JSON file at ``path``
        that was previously written by :meth:`export`.

        INPUT:

            - ``path`` -- string or path-like; Path to the JSON file.

        OUTPUT: A reconstructed :class:`Cipher` instance.
        """
        with open(path) as f:
            d = json.load(f)
        return cls._from_dict(d)

    def _latex_header(self, model_options, objective_value) -> str:
        r"""
        Returns the LaTeX preamble and document header for a trail report.
        """
        cryptanalysis_map = {
            CRYPTANALYSIS.DIFFERENTIAL: "differential",
            CRYPTANALYSIS.LINEAR: "linear",
        }
        granularity_map = {
            GRANULARITY.WORDWISE: "Wordwise",
            GRANULARITY.BITWISE: "Bitwise",
        }
        opt_map = {
            OPTIMIZATION.MILP: "MILP",
            OPTIMIZATION.SAT: "SAT",
        }
        for val, enum in [
            (model_options.cryptanalysis, CRYPTANALYSIS),
            (model_options.granularity, GRANULARITY),
            (model_options.optimization, OPTIMIZATION),
        ]:
            if val not in {
                CRYPTANALYSIS.DIFFERENTIAL,
                CRYPTANALYSIS.LINEAR,
                GRANULARITY.WORDWISE,
                GRANULARITY.BITWISE,
                OPTIMIZATION.MILP,
                OPTIMIZATION.SAT,
            }:
                raise InvalidModelOptionException(val, enum)

        cryptanalysis = cryptanalysis_map[model_options.cryptanalysis]
        granularity = granularity_map[model_options.granularity]
        milp_or_sat = opt_map[model_options.optimization]
        name = self.name.replace("_", "\\_")

        # define \statematrix as empty command so sub-ciphers can renewcommand
        STRING = "\\documentclass{article}\n"
        STRING += "\\usepackage{amssymb}\n"
        STRING += "\\usepackage{tikz}\n\\usepackage[margin=2cm]{geometry}\n"
        STRING += "\\usetikzlibrary{arrows}\n"
        STRING += "\\newcommand*{\\statematrix}[2]{}\n"
        STRING += f"\\title{{{granularity} {cryptanalysis} trail through "
        STRING += f"\\texttt{{{name}}} found by {milp_or_sat}}}\n\n"
        STRING += "\\author{\\texttt{CiVerLy}}\n"
        STRING += "\\begin{document}\n"
        STRING += "\\maketitle\n"

        return STRING

    def _write_and_compile_tex(self, string, model_options, _stem=None) -> None:
        r"""
        Writes ``string`` to a ``.tex`` file and compiles it to PDF via
        ``pdflatex``, then removes auxiliary build files.
        """
        stem = _stem if _stem is not None else self.name
        tex_file_name = model_options.path / (stem + ".tex")
        pdf_file_name = model_options.path / (stem + ".pdf")

        with open(tex_file_name, "w") as f:
            f.write(string)

        with suppress_output():
            process = subprocess.Popen(
                [
                    "pdflatex",
                    f"-output-directory={str(model_options.path)}",
                    "-synctex=1",
                    "-interaction=nonstopmode",
                    "-file-line-error",
                    "-recorder",
                    tex_file_name,
                ]
            )

        if process.wait() != 0:
            raise ChildProcessError("Error when compiling .tex file.")

        with suppress_output():
            prefix = str(model_options.path)
            for pattern in [
                "/*.synctex.gz",
                "/*.fls",
                "/*.aux",
                "/*.log",
                "/*.fdb_latexmk",
            ]:
                for f in glob.glob(prefix + pattern):
                    subprocess.Popen(["rm", "-f", f]).wait()

        print(f"Output file in: {pdf_file_name}")

    def _latex_section(self, trail_node, model_options) -> str:
        r"""
        Generate the LaTeX/tikz section string for this cipher, using the
        pre-built ``trail_node`` (which holds ``bits_in`` and ``bits_out``).
        Called by ``TrailNode.to_latex``.
        """
        from civerly.aeslike import AESlike

        depths = self._dfs_traversal()
        divide_by = (
            self.wordsize if model_options.granularity == GRANULARITY.WORDWISE else 1
        )

        space_between_layers = 3
        space_between_in_out = 2

        # Local copies so nibble-padding below does not mutate the node
        bits_in = [row[:] for row in trail_node.bits_in]
        bits_out = [row[:] for row in trail_node.bits_out]

        STRING = f"\\newpage\n"
        STRING += f"\\section{{{self.name.replace('_', '\\_')}}}\n"

        w = trail_node.weight
        if model_options.granularity == GRANULARITY.WORDWISE:
            STRING += f"Active SBoxes: ${w}$\n\n"
        elif model_options.granularity == GRANULARITY.BITWISE:
            obj_label = {
                CRYPTANALYSIS.DIFFERENTIAL: "differential probability",
                CRYPTANALYSIS.LINEAR: "linear correlation",
            }[model_options.cryptanalysis]
            STRING += f"Maximal {obj_label}: $2^{{-{w}}}$\n\n"

        STRING += "\\begingroup\n"

        if isinstance(self, AESlike):
            STRING += "\\renewcommand{\\statematrix}[2]{\n"
            STRING += (
                f"\t\\draw (#1, #2) rectangle (#1 + {self.cols}, #2 + {self.rows});\n"
            )
            for cl in range(self.cols):
                STRING += (
                    f"\t\\draw (#1 + {cl}, #2) -- (#1 + {cl}, #2 + {self.rows});\n"
                )
            for rw in range(self.rows):
                STRING += (
                    f"\t\\draw (#1, #2 + {rw}) -- (#1 + {self.cols}, #2 + {rw});\n"
                )
            STRING += "}\n"

        scale = sqrt((-0.75 + self._wrd / 4) * 4)

        STRING += "\\begin{center}\n"
        if isinstance(self, AESlike):
            STRING += "\t\\resizebox{0.7\\textwidth}{!}{\\begin{tikzpicture}\n"
        else:
            if scale * self.input_length // self._wrd > space_between_layers * max(
                depths
            ):
                STRING += "\t\\resizebox{0.7\\textwidth}{!}{\\begin{tikzpicture}\n"
            else:
                STRING += "\t\\resizebox{!}{0.8\\textheight}{\\begin{tikzpicture}\n"

        # Draw state arrays / component structure
        if isinstance(self, AESlike):
            for layer in range(max(depths) + 1):
                x_pos = (layer % 4) * (self.cols + 2)
                y_pos = -(layer // 4) * (self.rows + 1)
                STRING += f"\t\t\\statematrix{{{x_pos}}}{{{y_pos}}}\n"
                STRING += f"\t\t\\node[] at ({x_pos - 1}, {y_pos + 2})"
                STRING += "{\\huge $\\stackrel{ \\scriptsize "
                STRING += f"\\textrm{{{self.nodes[depths.index(layer)].name}}}"
                STRING += "}{\\longrightarrow}$};\n"
        else:  # SBoxCipher
            for (a, b), (x, y) in self.edges:
                xx = self._from_grid(
                    a, x // divide_by, model_options=model_options, input_side=False
                )
                yy = self._from_grid(
                    b, y // divide_by, model_options=model_options, input_side=True
                )

                top_a = -depths[a] * (space_between_layers + space_between_in_out)
                bot_b = -(
                    depths[b] * (space_between_layers + space_between_in_out)
                    - space_between_in_out
                    + 1
                )

                if b == self.nodes.index(self.OUT):
                    STRING += "\t\t\\draw[thin, dashed, ->] "
                else:
                    STRING += "\t\t\\draw[thin, ->] "
                STRING += f"({scale * divide_by * (0.5 + xx) / self._wrd}, "
                STRING += f"{top_a - space_between_in_out}) -- "
                STRING += f"({scale * divide_by * (0.5 + yy) / self._wrd}, "
                STRING += f"{bot_b});\n"

            for a, na in enumerate(self.nodes):
                if isinstance(na, Cipher.__Special_Node):
                    continue

                top = -depths[a] * (space_between_layers + space_between_in_out)
                bot = (
                    -depths[a] * (space_between_layers + space_between_in_out)
                    - space_between_in_out
                    + 1
                )

                if na.input_length > 0:
                    corner_a = (
                        scale
                        * divide_by
                        * self._from_grid(
                            a, 0, model_options=model_options, input_side=True
                        )
                        / self._wrd,
                        top,
                    )
                else:
                    corner_a = (
                        scale
                        * divide_by
                        * self._from_grid(
                            a,
                            na.output_length // (2 * divide_by),
                            model_options=model_options,
                            input_side=False,
                        )
                        / self._wrd,
                        top,
                    )

                corner_b = (
                    scale
                    * divide_by
                    * self._from_grid(
                        a, 0, model_options=model_options, input_side=False
                    )
                    / self._wrd,
                    bot,
                )
                corner_c = (
                    scale
                    * divide_by
                    * (
                        self._from_grid(
                            a,
                            (na.output_length - 1) // divide_by,
                            model_options=model_options,
                            input_side=False,
                        )
                        + 1
                    )
                    / self._wrd,
                    bot,
                )

                if na.input_length > 0:
                    corner_d = (
                        scale
                        * divide_by
                        * (
                            self._from_grid(
                                a,
                                (na.input_length - 1) // divide_by,
                                model_options=model_options,
                                input_side=True,
                            )
                            + 1
                        )
                        / self._wrd,
                        top,
                    )
                else:
                    corner_d = (
                        scale
                        * divide_by
                        * (
                            self._from_grid(
                                a,
                                na.output_length // (2 * divide_by),
                                model_options=model_options,
                                input_side=False,
                            )
                            + 1
                        )
                        / self._wrd,
                        top,
                    )

                mid_point = tuple(
                    sum(x) / 4 for x in zip(*[corner_a, corner_b, corner_c, corner_d])
                )

                STRING += f"\t\t\\draw[very thick] {corner_a} -- {corner_b} -- {corner_c} -- {corner_d} -- {corner_a};\n"
                STRING += f"\t\t\\node[] at {mid_point} {{\\tiny ${na.name.replace('_', '\\_')}$}};\n"

        # Convert raw bits to display arrays based on granularity
        if model_options.granularity == GRANULARITY.WORDWISE:
            arr_in = bits_in
            arr_out = bits_out
        elif model_options.granularity == GRANULARITY.BITWISE:
            for i in range(max(depths) + 1):  # pad to word boundary
                bits_in[i] += [0] * (-len(bits_in[i]) % self._wrd)
                bits_out[i] += [0] * (-len(bits_out[i]) % self._wrd)

            # Group bits into words for display
            nibbles_in = [
                [None] * (len(bits_in[d]) // self._wrd) for d in range(max(depths) + 1)
            ]
            nibbles_out = [
                [None] * (len(bits_out[d]) // self._wrd) for d in range(max(depths) + 1)
            ]
            for d in range(max(depths) + 1):
                nibbles_in[d] = [
                    sum(
                        bits_in[d][i : i + self._wrd][j] << (self._wrd - 1 - j)
                        for j in range(self._wrd)
                    )
                    for i in range(0, len(bits_in[d]), self._wrd)
                ]
                nibbles_out[d] = [
                    sum(
                        bits_out[d][i : i + self._wrd][j] << (self._wrd - 1 - j)
                        for j in range(self._wrd)
                    )
                    for i in range(0, len(bits_out[d]), self._wrd)
                ]
            arr_in = nibbles_in
            arr_out = nibbles_out

        # Fill in values
        bool_finished_arrin = False
        for j, arr_layer in enumerate(arr_in + arr_out):
            # restart the counter after we iterated through arr_in
            if j >= len(arr_in):
                bool_finished_arrin = True
                j -= len(arr_in)

            for i in range(len(arr_layer)):
                if arr_layer[i] is not None:  # Only draw the filled-in bits
                    if isinstance(self, AESlike):
                        if model_options.granularity == GRANULARITY.BITWISE:
                            tikz_entry = f"\\huge \\texttt{{ {arr_layer[i]:0{ceil(self._wrd / 4)}x} }}"
                        elif model_options.granularity == GRANULARITY.WORDWISE:
                            if arr_layer[i] in [1, "1"]:
                                tikz_entry = "$\\blacksquare$"
                            elif arr_layer[i] in [0, "0"]:
                                tikz_entry = "$\\square$"
                            else:
                                raise AssertionError(
                                    "Got a non-boolean value in the solution file"
                                )

                        # only draw output of each layer
                        if bool_finished_arrin:
                            STRING += "\t\t\\node[]"
                            STRING += f" at ({(j % 4) * (self.cols + 2) + (i // self.rows) + 0.5}, "
                            STRING += f"{-(j // 4) * (self.rows + 1) + self.rows - (i % self.rows) - 0.5})"
                            STRING += f"{{ {tikz_entry} }};\n"

                    else:  # SBoxCipher
                        if j == len(arr_out) - 1 and bool_finished_arrin:
                            continue  # skip self.OUT.out

                        computed_draw_depth = j * (
                            space_between_layers + space_between_in_out
                        )
                        if bool_finished_arrin:
                            computed_draw_depth += space_between_in_out

                        STRING += f"\t\t\\node[draw, minimum width={scale}cm, "
                        STRING += "minimum height=1cm] "
                        STRING += (
                            f"at ({(i + 0.5) * scale}, {-computed_draw_depth + 0.5})"
                        )

                        if model_options.granularity == GRANULARITY.BITWISE:
                            STRING += f"{{\\huge \\texttt{{{f'{arr_layer[i]:0{ceil(self._wrd / 4)}x}'}}}}};\n"

                        elif model_options.granularity == GRANULARITY.WORDWISE:
                            if arr_layer[i] in [1, "1"]:
                                tikz_entry = "$\\blacksquare$"
                            elif arr_layer[i] in [0, "0"]:
                                tikz_entry = "$\\square$"
                            else:
                                raise AssertionError(
                                    "Got a non-boolean value in the solution file"
                                )
                            STRING += f"{{{tikz_entry}}};\n"

        STRING += "\t\\end{tikzpicture}}\n\\end{center}\n\\endgroup\n"
        return STRING

    def exclude_solution(self, model_options, results):
        if model_options.optimization == OPTIMIZATION.MILP:
            return self._exclude_solution_milp(results)
        elif model_options.optimization == OPTIMIZATION.SAT:
            return self._exclude_solution_sat(results, model_options)

    def _exclude_solution_sat(self, results, model_options):
        input_file = model_options.path / (self.name + ".cnf")
        sum_arr_file = model_options.path / (self.name + "sum.json")

        with open(sum_arr_file) as f:
            sum_arr = json.load(f)

        sum_vars = {int(var) for _, var in sum_arr}
        input_vars = set(range(1, self.input_length + 1))
        blocking_var_list = sorted(sum_vars | input_vars)

        blocking_clause = tuple(
            (-v if results.get(v, 0) == 1 else v) for v in blocking_var_list
        )

        sat = DIMACS()
        sat.read(str(input_file))
        sat.add_clause(blocking_clause)
        sat.write(input_file)

    def _copy_over_dictionaries_recursively(self, prev, model_options):
        r"""
        Recursively copy the dictionaries and inv_dictionaries for each of the
        components from prev to self. Used in caching.
        """
        if model_options.optimization == OPTIMIZATION.MILP:
            self.dictionaries_milp = deepcopy(prev.dictionaries_milp)
            self.inv_dictionaries_milp = deepcopy(prev.inv_dictionaries_milp)
        elif model_options.optimization == OPTIMIZATION.SAT:
            self.dictionaries_sat = deepcopy(prev.dictionaries_sat)
            self.inv_dictionaries_sat = deepcopy(prev.inv_dictionaries_sat)

        for i in range(1, len(self.nodes)):
            self.nodes[i]._copy_over_dictionaries_recursively(
                prev.nodes[i], model_options
            )
