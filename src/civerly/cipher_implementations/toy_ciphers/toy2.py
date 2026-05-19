from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF
from civerly.sboxcipher import SBoxCipher
from civerly.component import LinearLayer_CVL, PermuteLayer_CVL


# linear cipher using rounds with intentionally missing
# structure of each layer
class Toy2:
    def __init__(self):
        r"""

        TESTS::

        The test code for SAT:
            sage: # optional - cryptominisat
            sage: from civerly.cipher_implementations.toy_ciphers.toy2 \
            ....:   import Toy2
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy2()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:       sat_solver=CRYPTOMINISAT_CVL(),
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            ....:   cipher.generate_report(model_options)
            1120 variables and 6177 clauses were written to '...'
            0
            Output file in: ...
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy2()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:       sat_solver=CRYPTOMINISAT_CVL(),
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            1408 variables and 3617 clauses were written to '...'
            0
            Output file in: ...

        The test code for MILP:
            sage: # optional - scip
            sage: from civerly.cipher_implementations.toy_ciphers.toy2 \
            ....:   import Toy2
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy2()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.MILP,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:       milp_solver=SOLVER.SCIP,
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            1472 variables and 1105 constraints were written to '...'
            0
            Output file in: ...
        """
        cipher = SBoxCipher(16, 16, name="Toy2")

        round = SBoxCipher(16, 16, name="Toy2-round")
        arr = [
            [1, 0, 0, 1, 0, 1, 1, 1],
            [1, 1, 1, 1, 0, 1, 1, 1],
            [0, 0, 0, 0, 1, 0, 1, 0],
            [1, 1, 0, 1, 1, 1, 0, 0],
            [0, 1, 1, 1, 1, 0, 1, 0],
            [0, 0, 0, 1, 0, 0, 1, 0],
            [1, 0, 0, 1, 1, 0, 1, 0],
            [0, 1, 0, 1, 0, 1, 0, 1]
        ]
        mat = matrix(GF(2), 8, arr)
        L1 = LinearLayer_CVL(mat, name="L1(8)")
        L2 = LinearLayer_CVL(mat, name="L2(8)")
        P1 = PermuteLayer_CVL(perm=[1, 3, 0, 2], word_coarseness=4, name="P1(16)")
        P2 = PermuteLayer_CVL(perm=[0, 2, 1, 3], word_coarseness=4, name="P2(16)")
        P3 = PermuteLayer_CVL(perm=[2, 0, 3, 1], word_coarseness=4, name="P3(16)")

        node_in = round.add_subcipher(P1, [(round.IN, (i, i)) for i in range(16)])
        node1 = round.add_subcipher(L1, [(node_in, (i, i)) for i in range(8)])
        node2 = round.add_subcipher(L2, [(node_in, (i+8, i)) for i in range(8)])
        node_mid = round.add_subcipher(P2, [(node1, (i, i+8)) for i in range(8)] + [(node2, (i, i)) for i in range(8)])
        node3 = round.add_subcipher(L1, [(node_mid, (i, i)) for i in range(8)])
        node4 = round.add_subcipher(L2, [(node_mid, (i+8, i)) for i in range(8)])
        node_out = round.add_subcipher(P3, [(node3, (i, i)) for i in range(8)] + [(node4, (i, i+8)) for i in range(8)])
        round.add_output([(node_out, (i, i)) for i in range(16)])

        node = cipher.IN
        for r in range(4):
            node = cipher.add_subcipher(round, [(node, (i, i)) for i in range(16)])
        cipher.add_output([(node, (i, i)) for i in range(16)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(Toy2, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
