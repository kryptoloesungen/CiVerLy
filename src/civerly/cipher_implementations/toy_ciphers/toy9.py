from civerly.sboxcipher import SBoxCipher
from civerly.component import SBox_CVL
from sage.crypto.sboxes import GIFT as gift_S


# cipher using sboxes with transition of non-integer weight
class Toy9:
    def __init__(self):
        r"""

        TESTS::

            sage: # optional - gurobi # optional - espresso
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
            ....:       milp_solver=GUROBI_CVL(),
            ....:       logic_minimizer=ESPRESSO_CVL(),
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
            ....:       sat_solver=CRYPTOMINISAT_CVL(),
            ....:       logic_minimizer=ESPRESSO_CVL(),
            ....:       path=Path(tmpdir))
            ....:   cipher.analyse(model_options)
            36 variables and 109 clauses were written to '...'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 ,  6] (trying w =   3) : SAT
            [  0 ,  3] (trying w =   1) : SAT
            [  0 ,  1] (trying w =   0) : UNSAT
            1

        Testing workflow of `Cipher.load`:

            sage: # optional - scip # optional - espresso
            sage: from civerly.cipher_implementations.toy_ciphers.toy9 \
            ....:   import Toy9
            sage: from civerly.model_options import *
            sage: from pathlib import Path
            sage: import tempfile
            sage: cipher = Toy9()
            sage: with tempfile.TemporaryDirectory(delete=False) as tmpdir:
            ....:   model_options = MODEL_OPTIONS(
            ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:       optimization=OPTIMIZATION.MILP,
            ....:       granularity=GRANULARITY.BITWISE,
            ....:       sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:       milp_solver=SCIP_CVL(),
            ....:       logic_minimizer=ESPRESSO_CVL(),
            ....:       path=Path(tmpdir))
            sage: cipher.analyse(model_options)
            sage: export_path = model_options.path / f"{cipher.name}.json"
            sage: cipher.export(export_path)
            Writing problem data to ...
            335 records were written
            Object 'toy9' has been exported to ...
            sage: from civerly.sboxcipher import SBoxCipher
            sage: from civerly.wordsboxcipher import WordSBoxCipher
            sage: loaded1 = SBoxCipher.load(export_path)
            sage: import shutil
            sage: shutil.rmtree(model_options.path)
        """

        cipher = SBoxCipher(4, 4, name="toy9")
        s = SBox_CVL(gift_S, name="S")  # 4 -> 4
        node = cipher.add_subcipher(s, [(cipher.IN, (i, i)) for i in range(4)])
        cipher.add_output([(node, (i, i)) for i in range(4)])

        self.cipher = cipher

    def __new__(cls, *args, **kwargs):
        instance = super(Toy9, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.cipher
