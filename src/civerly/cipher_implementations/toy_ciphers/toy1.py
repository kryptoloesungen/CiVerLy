from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF
from civerly.sboxcipher import SBoxCipher
from civerly.component import LinearLayer_CVL, PermuteLayer_CVL


# linear cipher with non-bijective LinearLayer_CVL's, different intermediate
# state sizes and direct in- out- connection
class Toy1:
    def __init__(self):
        r"""

        TESTS::

            sage: from civerly.cipher_implementations.toy_ciphers.toy1 \
            ....:   import Toy1
            sage: from civerly.model_options import *
            sage: import tempfile

        The test code for SAT:
            sage: # optional - cryptominisat
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy1()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:       sat_solver=CRYPTOMINISAT_CVL(),
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            382 variables and 1527 clauses were written to '...'
            0
            Output file in: ...
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy1()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:       sat_solver=CRYPTOMINISAT_CVL(),
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            382 variables and 1003 clauses were written to '...'
            0
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy1()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:       sat_solver=CRYPTOMINISAT_CVL(),
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            426 variables and 955 clauses were written to '...'
            0

        The test code for MILP:

            sage: from civerly.cipher_implementations.toy_ciphers.toy1 import Toy1
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - gurobi
            ....:   cipher = Toy1()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.MILP,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:       milp_solver=GUROBI_CVL(),
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            474 variables and 346 constraints were written to '...'
            ...
            0
            sage: from civerly.cipher_implementations.toy_ciphers.toy1 import Toy1
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   cipher = Toy1()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.MILP,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:       milp_solver=SCIP_CVL(),
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            474 variables and 346 constraints were written to '...'
            ...
            0
            sage: from civerly.cipher_implementations.toy_ciphers.toy1 import Toy1
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - glpk
            ....:   cipher = Toy1()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.MILP,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:       milp_solver=GLPK_CVL(),
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            474 variables and 346 constraints were written to '...'
            ...
            0
            sage: from civerly.cipher_implementations.toy_ciphers.toy1 import Toy1
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - scip
            ....:   cipher = Toy1()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:       optimization=OPTIMIZATION.MILP,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       milp_solver=SCIP_CVL(),
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            486 variables and 350 constraints were written to '...'
            0

        """
        cipher = SBoxCipher(37, 37, name="Toy1")

        P = PermuteLayer_CVL(perm=[1, 3, 0, 2], word_coarseness=4, name="P(16)")

        arr = [
            [1, 0, 0, 1, 0, 1, 1, 1],
            [1, 1, 1, 1, 0, 1, 1, 1],
            [0, 0, 0, 0, 1, 0, 1, 0],
            [1, 1, 0, 1, 1, 1, 0, 0]
        ]
        mat = matrix(GF(2), 4, 8, arr)
        L1 = LinearLayer_CVL(mat, name="L(8->4)")
        arr = [
            [0, 0, 1, 1],
            [1, 0, 1, 1],
            [0, 1, 0, 0],
            [1, 1, 1, 0],
            [1, 1, 0, 0],
            [0, 0, 0, 0],
            [0, 1, 0, 0],
            [1, 0, 1, 1]
        ]
        mat = matrix(GF(2), 8, 4, arr)
        L2 = LinearLayer_CVL(mat, name="L(4->8)")

        node1 = cipher.add_subcipher(P, [(cipher.IN, (i, i)) for i in range(16)])
        node2 = cipher.add_subcipher(P, [(cipher.IN, (i+16, i)) for i in range(16)])

        node_new = [None for _ in range(4)]
        for j in range(4):
            node_new[j] = cipher.add_subcipher(
                L1,
                [
                    (node1, (i + 4*j, i)) for i in range(4)
                ] + [
                    (node2, (i + 4*j, i + 4)) for i in range(4)
                ]
            )
            node_new[j] = cipher.add_subcipher(
                L2, [(node_new[j], (i, i)) for i in range(4)]
            )
            cipher.add_output([(node_new[j], (i, i + 8*j)) for i in range(8)])

        cipher.add_output([(cipher.IN, (i, i)) for i in range(32, 37)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(Toy1, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
