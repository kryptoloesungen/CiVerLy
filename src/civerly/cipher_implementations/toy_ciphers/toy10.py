from sage.crypto.sbox import SBox
from sage.matrix.constructor import Matrix as matrix
from sage.rings.finite_rings.finite_field_constructor import GF

from civerly.component import LinearLayer_CVL, SBox_CVL
from civerly.sboxcipher import SBoxCipher


# cipher testing whether linear modeling is the same for the following
# cases:
#   - Either, when a normal 6 -> 6 linear layer is used
#   - or when that linear layer is seperately defined by its coordinate
#     functions which are 6 -> 1 and therefore non-bijective.
class Toy10:
    def __init__(self, split=False):
        r"""

        TESTS::

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.toy_ciphers.toy10 \
            ....:   import Toy10
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy10(False)
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:       sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:       sat_solver=SOLVER.CRYPTOMINISAT,
            ....:       logic_minimizer=SOLVER.ESPRESSO,
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            92 variables and 288 clauses were written to '...'
            1

            sage: # optional - cadical # optional - espresso
            sage: from civerly.cipher_implementations.toy_ciphers.toy10 \
            ....:   import Toy10
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy10(False)
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:       sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:       sat_solver=SOLVER.CADICAL,
            ....:       logic_minimizer=SOLVER.ESPRESSO,
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            92 variables and 288 clauses were written to '...'
            1

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.toy_ciphers.toy10 \
            ....:   import Toy10
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy10(True)
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:       sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:       sat_solver=SOLVER.CRYPTOMINISAT,
            ....:       logic_minimizer=SOLVER.ESPRESSO,
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            122 variables and 690 clauses were written to '...'
            1

            sage: # optional - scip # optional - espresso
            sage: from civerly.cipher_implementations.toy_ciphers.toy10 \
            ....:   import Toy10
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy10(True)
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:       optimization=OPTIMIZATION.MILP,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:       linear_layer_modeling=LINEAR_LAYER_MODELING.MORE_DUMMIES,
            ....:       milp_solver=SOLVER.SCIP,
            ....:       logic_minimizer=SOLVER.ESPRESSO,
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            128 variables and 702 constraints were written to '...'
            1

        """

        round = SBoxCipher(6, 6, name="toy10-round")
        cipher = SBoxCipher(6, 4, name="toy10")
        round._wrd = 6
        arr = [
            [1, 0, 0, 0, 0, 0],
            [0, 1, 0, 0, 0, 0],
            [0, 0, 1, 0, 0, 0],
            [0, 0, 0, 1, 0, 0],
            [0, 0, 0, 0, 1, 0],
            [0, 0, 0, 0, 0, 1],
        ]
        if not split:
            mat = matrix(GF(2), arr)
            ll = LinearLayer_CVL(mat, name="L")

            node = round.add_subcipher(ll, [(round.IN, (i, i)) for i in range(6)])
            round.add_output([(node, (i, i)) for i in range(6)])
        else:  # split up the linear layer and see if its the same
            for j in range(6):
                mat = matrix(GF(2), arr[j])
                ll = LinearLayer_CVL(mat, name=f"L{j}")
                assert ll.input_length == 6 and ll.output_length == 1

                node = round.add_subcipher(ll, [(round.IN, (i, i)) for i in range(6)])
                round.add_output([(node, (0, j))])

        node1 = cipher.add_subcipher(round, [(cipher.IN, (i, i)) for i in range(6)])

        S = SBox(
            (
                14,
                4,
                13,
                1,
                2,
                15,
                11,
                8,
                3,
                10,
                6,
                12,
                5,
                9,
                0,
                7,
                0,
                15,
                7,
                4,
                14,
                2,
                13,
                1,
                10,
                6,
                12,
                11,
                9,
                5,
                3,
                8,
                4,
                1,
                14,
                8,
                13,
                6,
                2,
                11,
                15,
                12,
                9,
                7,
                3,
                10,
                5,
                0,
                15,
                12,
                8,
                2,
                4,
                9,
                1,
                7,
                5,
                11,
                3,
                14,
                10,
                0,
                6,
                13,
            )
        )

        node2 = cipher.add_subcipher(
            SBox_CVL(S, name="S"), [(node1, (i, i)) for i in range(6)]
        )
        cipher.add_output([(node2, (i, i)) for i in range(4)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(Toy10, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
