from civerly.andrx import AndRX
from civerly.component import AND_CVL, XOR_CVL, RotateLayer_CVL, RoundkeyXOR_CVL
from civerly.component import ROT_AND_CVL


class SIMON_Variants_CVL:
    def __init__(self, block_size, R, params=[8, 1, 2], rks=[],
                 use_rotand=True, name=None):
        r"""
        TESTS::

            sage: from civerly.cipher_implementations.simon import SIMON_CVL
            sage: from civerly.cipher_implementations.simon_variants \
            ....:   import SIMON_Variants_CVL
            sage: real_simon = SIMON_CVL(32, 64, R=4, use_rotand=True)
            sage: simon = SIMON_Variants_CVL(
            ....:   32, R=4, params=[8, 1, 2], use_rotand=True)
            sage: simon == real_simon
            True

        Different parameter sets can impact the differential bounds on
        6 round SIMON-32::

            sage: from civerly.cipher_implementations.simon_variants \
            ....:   import SIMON_Variants_CVL
            sage: cipher = SIMON_Variants_CVL(
            ....:   32, R=6, params=[11, 10, 0], use_rotand=True)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(4, 10),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            2982 variables and 6861 clauses were written to '...'
            [  4 , 10] (trying w =   7) : UNSAT
            [  8 , 10] (trying w =   9) : SAT
            [  8 ,  9] (trying w =   8) : SAT
            8

            sage: from civerly.cipher_implementations.simon_variants \
            ....:   import SIMON_Variants_CVL
            sage: cipher = SIMON_Variants_CVL(
            ....:   32, R=6, params=[11, 3, 9], use_rotand=True)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(4, 10),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            3216 variables and 7329 clauses were written to '...'
            [  4 , 10] (trying w =   7) : SAT
            [  4 ,  7] (trying w =   5) : UNSAT
            [  6 ,  7] (trying w =   6) : SAT
            6

            sage: from civerly.cipher_implementations.simon_variants \
            ....:   import SIMON_Variants_CVL
            sage: cipher = SIMON_Variants_CVL(
            ....:   32, R=6, params=[13, 14, 5], use_rotand=True)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(4, 10),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            2982 variables and 6861 clauses were written to '...'
            [  4 , 10] (trying w =   7) : UNSAT
            [  8 , 10] (trying w =   9) : UNSAT
            [ 10 , 10] (trying w =  10) : SAT
            10

            sage: from civerly.cipher_implementations.simon_variants \
            ....:   import SIMON_Variants_CVL
            sage: cipher = SIMON_Variants_CVL(
            ....:   32, R=6, params=[8, 1, 2], use_rotand=True)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(8, 16),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            2982 variables and 6861 clauses were written to '...'
            [  8 , 16] (trying w =  12) : SAT
            [  8 , 12] (trying w =  10) : UNSAT
            [ 11 , 12] (trying w =  11) : UNSAT
            12

        As stated in [KLT15], there exist parameters which yield an optimal
        weight of 26 for 10 rounds SIMON-32, which is better compared to the
        bound 25 given by the standard parameter set `[8, 1, 2]`::

            sage: from civerly.cipher_implementations.simon_variants \
            ....:   import SIMON_Variants_CVL
            sage: cipher = SIMON_Variants_CVL(
            ....:   32, R=10, params=[8, 1, 2], use_rotand=True)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(24, 26),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            4842 variables and 11221 clauses were written to '...'
            [ 24 , 26] (trying w =  25) : SAT
            [ 24 , 25] (trying w =  24) : UNSAT
            25

            sage: from civerly.cipher_implementations.simon_variants \
            ....:   import SIMON_Variants_CVL
            sage: cipher = SIMON_Variants_CVL(
            ....:   32, R=10, params=[1, 0, 2], use_rotand=True)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(24, 26),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            4842 variables and 11221 clauses were written to '...'
            [ 24 , 26] (trying w =  25) : UNSAT
            [ 26 , 26] (trying w =  26) : SAT
            26

            sage: from civerly.cipher_implementations.simon_variants \
            ....:   import SIMON_Variants_CVL
            sage: cipher = SIMON_Variants_CVL(
            ....:   32, R=10, params=[11, 0, 6], use_rotand=True)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(24, 26),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            4842 variables and 11221 clauses were written to '...'
            [ 24 , 26] (trying w =  25) : UNSAT
            [ 26 , 26] (trying w =  26) : SAT
            26

        Scaling every parameter in SIMON by the same amount should leave
        the trails unchanged, similar to doubleAES having the same bound
        as AES::

            sage: from civerly.util import suppress_output
            sage: import random
            sage: N = random.randint(1, 6)
            sage: from civerly.cipher_implementations.simon_variants \
            ....:   import SIMON_Variants_CVL
            sage: cipher = SIMON_Variants_CVL(
            ....:   N*32, R=4, params=[8*N, 1*N, 2*N], use_rotand=True)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(4, 8),
            ....:     path=Path(tmpdir))
            ....:   with suppress_output():
            ....:     bound = cipher.analyse(model_options=model_options)
            ....:   print(bound)
            6

        """

        if name is None:
            name = "simon"

        n = int(block_size // 2)
        if rks == []:
            rks = [0 for _ in range(R+1)]

        # SIMON is an AndRX cipher, since its non-linear component
        # is logical AND.
        simon_round = AndRX(n, 2, 2, name="simon_round")

        # Initialization of components
        # ------------------------------------------------ #
        rot_1 = RotateLayer_CVL(n, params[0], name=f"rotate{params[0]}")
        rot_2 = RotateLayer_CVL(n, params[1], name=f"rotate{params[1]}")
        rot_3 = RotateLayer_CVL(n, params[2], name=f"rotate{params[2]}")
        and1 = AND_CVL(n, name="and")
        xor = XOR_CVL(n, name="xor")
        key_add = RoundkeyXOR_CVL(n, 0x0, name="rk")
        ra1 = ROT_AND_CVL(
            n, params[0] - params[1], name=f"rot_and{params[0] - params[1]}"
        )
        # ------------------------------------------------ #

        # Implementation of SIMON round
        # ------------------------------------------------ #
        # insert RotateLayer_CVL + AND_CVL components
        if not use_rotand:
            node_rot_2 = simon_round.add_subcipher(
                rot_2, [(simon_round.IN, (0, 0))]
            )
            node_rot_1 = simon_round.add_subcipher(
                rot_1, [(simon_round.IN, (0, 0))]
            )
            node_and = simon_round.add_subcipher(
                and1, [(node_rot_2, (0, 0)), (node_rot_1, (0, 1))]
            )
            node_xor1 = simon_round.add_subcipher(
                xor,  [(node_and, (0, 0)), (simon_round.IN, (1, 1))]
            )
        # insert ROT_AND_CVL component
        else:
            node_rot_2 = simon_round.add_subcipher(
                rot_2, [(simon_round.IN, (0, 0))]
            )
            node_rot_and = simon_round.add_subcipher(
                ra1,  [(node_rot_2, (0, 0))]
            )
            node_xor1 = simon_round.add_subcipher(
                xor,  [(node_rot_and, (0, 0)), (simon_round.IN, (1, 1))]
            )

        node_rot_3 = simon_round.add_subcipher(
            rot_3, [(simon_round.IN, (0, 0))]
        )
        node_xor2 = simon_round.add_subcipher(
            xor,  [(node_xor1, (0, 0)), (node_rot_3, (0, 1))]
        )
        node_keyxor = simon_round.add_subcipher(
            key_add, [(node_xor2, (0, 0))]
        )
        simon_round.add_output(
            [(node_keyxor, (0, 0)), (simon_round.IN, (0, 1))]
        )
        # ------------------------------------------------ #

        # Adding SIMON rounds into the cipher
        # ------------------------------------------------ #
        # SIMON operates on two words of size n.
        simon_cipher = AndRX(n, 2, 2, name=name)

        node = simon_cipher.IN
        for r in range(R):
            simon_round.nodes[node_keyxor].const = rks[r]
            node = simon_cipher.add_subcipher(
                simon_round, [(node, (0, 0)), (node, (1, 1))]
            )
        simon_cipher.add_output([(node, (0, 0)), (node, (1, 1))])
        # ------------------------------------------------ #

        simon_cipher._rk_components = [
            simon_cipher.nodes[r+1].nodes[node_keyxor] for r in range(R)
        ]
        simon_cipher.key_schedule = None

        self.simon_cipher = simon_cipher

    def __new__(cls, *args, **kwargs):
        instance = super(SIMON_Variants_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.simon_cipher
