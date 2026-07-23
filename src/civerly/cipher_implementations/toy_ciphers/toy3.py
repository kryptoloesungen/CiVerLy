from sage.crypto.sboxes import PRESENT
from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF

from civerly.component import I_CVL, LinearLayer_CVL, PermuteLayer_CVL, SBox_CVL
from civerly.sboxcipher import SBoxCipher


# sbox cipher with missing structure of each layer
class Toy3:
    def __init__(self):
        r"""

        TESTS::

        The test code for SAT:

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.toy_ciphers.toy3 \
            ....:   import Toy3
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy3()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:       sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:       sat_solver=SOLVER.CRYPTOMINISAT,
            ....:       logic_minimizer=SOLVER.ESPRESSO,
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            ....:   cipher.generate_report(model_options)
            ....:   cipher = Toy3()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:       sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:       sat_solver=SOLVER.CRYPTOMINISAT,
            ....:       logic_minimizer=SOLVER.ESPRESSO,
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            ....:   cipher.generate_report(model_options)
            798 variables and 3591 clauses were written to '...'
            8
            Output file in: ...
            Using existing file ..., make sure it is up to date!
            812 variables and 3563 clauses were written to '...'
            8
            Output file in: ...

        The test code for MILP:

            sage: # optional - scip
            sage: from civerly.cipher_implementations.toy_ciphers.toy3 \
            ....:   import Toy3
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy3()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.MILP,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:       sbox_modeling=SBOX_MODELING.CONVEX_HULL,
            ....:       milp_solver=SOLVER.SCIP,
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            ....:   cipher.generate_report(model_options)
            854 variables and 1313 constraints were written to '...'
            8
            Output file in: ...
        """
        cipher = SBoxCipher(32, 32, name="Toy3")
        S = SBox_CVL(PRESENT, name="S")
        mat = matrix(GF(2), [[1, 0, 0, 1], [1, 0, 1, 0], [0, 0, 1, 0], [1, 1, 1, 1]])
        L = LinearLayer_CVL(mat, name="L")
        P = PermuteLayer_CVL([7, 5, 6, 1, 2, 3, 0, 4], word_coarseness=4, name="P")
        edge_arr = []
        for j in range(8):
            if j == 5:
                continue
            node = cipher.add_subcipher(
                S, [(cipher.IN, (i + 4 * j, i)) for i in range(4)]
            )
            node = cipher.add_subcipher(S, [(node, (i, 3 - i)) for i in range(4)])
            node = cipher.add_subcipher(S, [(node, ((i + 1) % 4, i)) for i in range(4)])
            node = cipher.add_subcipher(S, [(node, (i, i)) for i in range(4)])
            node = cipher.add_subcipher(L, [(node, (i, i)) for i in range(4)])
            edge_arr += [(node, (i, i + 4 * j)) for i in range(4)]

        I = I_CVL(4, name="I(4)")  # noqa: E741

        node = cipher.add_subcipher(S, [(cipher.IN, (i + 4 * 5, i)) for i in range(4)])
        node = cipher.add_subcipher(I, [(node, (i, 3 - i)) for i in range(4)])
        node = cipher.add_subcipher(I, [(node, ((i + 1) % 4, i)) for i in range(4)])
        node = cipher.add_subcipher(I, [(node, (3 - i, i)) for i in range(4)])
        node = cipher.add_subcipher(S, [(node, (i, i)) for i in range(4)])
        edge_arr += [(node, (i, i + 4 * 5)) for i in range(4)]

        node_out = cipher.add_subcipher(P, edge_arr)

        for j in range(4):
            node = cipher.add_subcipher(
                S, [(node_out, ((i + 4 * j + 3) % 16, i)) for i in range(4)]
            )
            node = cipher.add_subcipher(S, [(node, (i, i)) for i in range(4)])
            cipher.add_output([(node, (i, i + 4 * j)) for i in range(4)])
        for j in range(4, 8):
            node = cipher.add_subcipher(
                S, [(node_out, (i + 4 * j, i)) for i in range(4)]
            )
            cipher.add_output([(node, (i, i + 4 * j)) for i in range(4)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(Toy3, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
