from sage.crypto.sboxes import GIFT as gift_S

from civerly.component import SBox_CVL
from civerly.sboxcipher import SBoxCipher


# cipher using sboxes with transition of non-integer weight
class Toy9(SBoxCipher):
    def __init__(self):
        r"""

        TESTS::

            sage: # optional - scip # optional - espresso
            sage: from civerly.cipher_implementations.toy_ciphers.toy9 \
            ....:   import Toy9
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy9()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.MILP,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:       milp_solver=SOLVER.SCIP,
            ....:       logic_minimizer=SOLVER.ESPRESSO,
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            36 variables and 85 constraints were written to '...'
            1.4150374993

            sage: # optional - cryptominisat # optional - espresso
            sage: from civerly.cipher_implementations.toy_ciphers.toy9 \
            ....:   import Toy9
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:
            ....:   cipher = Toy9()
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.SAT,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:       sat_solver=SOLVER.CRYPTOMINISAT,
            ....:       logic_minimizer=SOLVER.ESPRESSO,
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            36 variables and 109 clauses were written to '...'
            1

        """
        super().__init__(4, 4, name="toy9")

        s = SBox_CVL(gift_S, name="S")  # 4 -> 4
        node = self.add_subcipher(s, [(self.IN, (i, i)) for i in range(4)])
        self.add_output([(node, (i, i)) for i in range(4)])
