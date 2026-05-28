from civerly.andrx import AndRX
from civerly.component import AND_CVL, XOR_CVL, RotateLayer_CVL, RoundkeyXOR_CVL
from civerly.component import ROT_AND_CVL

# Dictionary to determine the number of rounds, based on the cipher parameters.
# Has the form: dictionary[(block_size,key_size)] = R
dictionary = {
    (32, 64): 32, (48, 72): 36, (48, 96): 36, (64, 96): 42, (64, 128): 44,
    (96, 96): 52, (96, 144): 56, (128, 128): 68,
    (128, 192): 69, (128, 256): 72
}


class SIMON_CVL:
    def __init__(self, block_size, key_size, R=None, rks=[], use_rotand=True,
                 name=None):
        r"""
        The CiVerLy implementation of SIMON. It takes the following arguments:

            - ``block_size``-- integer; Determines the block size of the SIMON
              instance. Together with ``key_size``, it determines the
              SIMON-2n-mn instance.

            - ``key_size``-- integer; Determines the key size of the SIMON
              instance. Together with ``block_size``, it determines the
              SIMON-2n-mn instance.

            - ``rks`` -- list (optional); Specifies the roundkey values of
              SIMON, in order to being able to properly test the
              implementation. Is required to have length ``R+1``, and defaults
              to ``[0, ..., 0]``.

            - ``name`` -- string (optional); The name of the cipher.
              Will be used to name the cipher and the corresponding files
              generated (such as the reports and cipher graphs).

        This cipher is "plug-and-play" usable, i.e. it can be directly used
        when imported. SIMON can be implemented in two different ways, either
        using seperate `RotateLayer_CVL` and `AND_CVL` components, or by
        combining them into a dedicated `ROT_AND_CVL` component. The second
        option allows for more precise results when modeling, as the modeling
        methods from https://eprint.iacr.org/2015/145.pdf are used instead of
        treating the inputs as independent.


        EXAMPLES::

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.simon import SIMON_CVL
            sage: simon_cipher = SIMON_CVL(64,128)
            sage: hex(vec_to_int(simon_cipher(int_to_vec(0xabcd1234, 64))))
            '0xa26a16020880adbd'

        TESTS::

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.simon import SIMON_CVL
            sage: P = 0x6f7220676e696c63
            sage: rks = [
            ....:   0x03020100, 0x0b0a0908, 0x13121110, 0xffae9dce, 0xc4facc91,
            ....:   0xc83d1bb6, 0xb5d510ff, 0x36e2c07c, 0x72709043, 0x1343f40e,
            ....:   0xea417e40, 0x9e635793, 0xa6965478, 0x8b052e75, 0x884c5f47,
            ....:   0xd0e4e598, 0xe3e80363, 0x35f020e1, 0x1afa1c76, 0xbee71ed6,
            ....:   0x763d4d2a, 0x0ca19efc, 0x0046cb1b, 0x59ce0704, 0x3dfb4191,
            ....:   0xcbd9e8cc, 0xf3f75b6d, 0xa34520b7, 0xba7ae12d, 0x60e056a6,
            ....:   0xf6a8d0f4, 0x943a89c1, 0xb4db50fe, 0x3481f018, 0xee1d573f,
            ....:   0x4806d097, 0x56feb8ff, 0x0e529452, 0xd6d654a4, 0x7eb6e8dd,
            ....:   0x8990d838,0xb082bddc]
            sage: C = 0x5ca2e27f111a8fc8
            sage: V, W = 64, 96
            sage: simon_cipher = SIMON_CVL(V, W, rks=rks)
            sage: vec_to_int(simon_cipher(int_to_vec(P, V))) == C
            True

        Models for differential cryptanalysis::

            sage: from civerly.cipher_implementations.simon import SIMON_CVL
            sage: cipher = SIMON_CVL(32, 64, R=8, use_rotand=False)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(16, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            4160 variables and 8641 clauses were written to '...'
            [ 16 , 20] (trying w =  18) : SAT
            [ 16 , 18] (trying w =  17) : UNSAT
            18

            sage: from civerly.cipher_implementations.simon import SIMON_CVL
            sage: cipher = SIMON_CVL(32, 64, R=8, use_rotand=True)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(16, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            3912 variables and 9041 clauses were written to '...'
            [ 16 , 20] (trying w =  18) : SAT
            [ 16 , 18] (trying w =  17) : UNSAT
            18

            sage: from civerly.cipher_implementations.simon import SIMON_CVL
            sage: cipher = SIMON_CVL(32, 64, R=8, use_rotand=False)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cadical  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CADICAL_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(16, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            4160 variables and 8641 clauses were written to '...'
            [ 16 , 20] (trying w =  18) : SAT
            [ 16 , 18] (trying w =  17) : UNSAT
            18

            sage: from civerly.cipher_implementations.simon import SIMON_CVL
            sage: cipher = SIMON_CVL(32, 64, R=8, use_rotand=True)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cadical  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CADICAL_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(16, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            3912 variables and 9041 clauses were written to '...'
            [ 16 , 20] (trying w =  18) : SAT
            [ 16 , 18] (trying w =  17) : UNSAT
            18

        Models for linear cryptanalysis. The results are from Table 1 in
        https://eprint.iacr.org/2015/145.pdf, which uses squared
        correlations::

            sage: from civerly.cipher_implementations.simon import SIMON_CVL
            sage: cipher = SIMON_CVL(32, 64, R=11, use_rotand=False)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(10, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            5648 variables and 13169 clauses were written to '...'
            [ 10 , 20] (trying w =  15) : SAT
            [ 10 , 15] (trying w =  12) : UNSAT
            [ 13 , 15] (trying w =  14) : UNSAT
            15

            sage: from civerly.cipher_implementations.simon import SIMON_CVL
            sage: cipher = SIMON_CVL(32, 64, R=11, use_rotand=True)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(10, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            6000 variables and 12817 clauses were written to '...'
            [ 10 , 20] (trying w =  15) : SAT
            [ 10 , 15] (trying w =  12) : UNSAT
            [ 13 , 15] (trying w =  14) : UNSAT
            15

            sage: from civerly.cipher_implementations.simon import SIMON_CVL
            sage: cipher = SIMON_CVL(32, 64, R=11, use_rotand=False)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cadical  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CADICAL_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(10, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            5648 variables and 13169 clauses were written to '...'
            [ 10 , 20] (trying w =  15) : SAT
            [ 10 , 15] (trying w =  12) : UNSAT
            [ 13 , 15] (trying w =  14) : UNSAT
            15

            sage: from civerly.cipher_implementations.simon import SIMON_CVL
            sage: cipher = SIMON_CVL(32, 64, R=11, use_rotand=True)
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cadical  # optional - espresso
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=CADICAL_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(10, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            6000 variables and 12817 clauses were written to '...'
            [ 10 , 20] (trying w =  15) : SAT
            [ 10 , 15] (trying w =  12) : UNSAT
            [ 13 , 15] (trying w =  14) : UNSAT
            15

        """
        if name is None:
            name = "simon"

        n = int(block_size // 2)
        if R is None:
            R = dictionary[(block_size, key_size)]
        if rks == []:
            rks = [0 for _ in range(R+1)]

        # SIMON is an AndRX cipher, since its non-linear component
        # is logical AND.
        simon_round = AndRX(n, 2, 2, name="simon_round")

        # Initialization of components
        # ------------------------------------------------ #
        rot1 = RotateLayer_CVL(n, 1, name="rotate1")
        rot2 = RotateLayer_CVL(n, 2, name="rotate2")
        rot8 = RotateLayer_CVL(n, 8, name="rotate8")
        and1 = AND_CVL(n, name="and")
        xor = XOR_CVL(n, name="xor")
        key_add = RoundkeyXOR_CVL(n, 0x0, name="rk")
        ra1 = ROT_AND_CVL(n, 7, name="rot_and7")
        # ------------------------------------------------ #

        # Implementation of SIMON round
        # ------------------------------------------------ #
        if not use_rotand:  # insert RotateLayer_CVL + AND_CVL components
            node_rot1 = simon_round.add_subcipher(
                rot1, [(simon_round.IN, (0, 0))]
            )
            node_rot8 = simon_round.add_subcipher(
                rot8, [(simon_round.IN, (0, 0))]
            )
            node_and = simon_round.add_subcipher(
                and1, [(node_rot1, (0, 0)), (node_rot8, (0, 1))]
            )
            node_xor1 = simon_round.add_subcipher(
                xor,  [(node_and, (0, 0)), (simon_round.IN, (1, 1))]
            )
        else:              # insert ROT_AND_CVL component
            node_rot1 = simon_round.add_subcipher(
                rot1, [(simon_round.IN, (0, 0))]
            )
            node_rot_and = simon_round.add_subcipher(
                ra1,  [(node_rot1, (0, 0))]
            )
            node_xor1 = simon_round.add_subcipher(
                xor,  [(node_rot_and, (0, 0)), (simon_round.IN, (1, 1))]
            )

        node_rot2 = simon_round.add_subcipher(
            rot2, [(simon_round.IN, (0, 0))]
        )
        node_xor2 = simon_round.add_subcipher(
            xor,  [(node_xor1, (0, 0)), (node_rot2, (0, 1))]
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

        # Collect references to all RoundkeyXOR_CVL components for key schedule
        # support. Each entry points to the KeyAdd component inside the
        # corresponding round node. Set key_schedule to a callable returning
        # R round keys to enable set_round_keys(k).
        # ------------------------------------------------ #
        simon_cipher._rk_components = [
            simon_cipher.nodes[r+1].nodes[node_keyxor] for r in range(R)
        ]
        simon_cipher.key_schedule = None

        self.simon_cipher = simon_cipher

    def __new__(cls, *args, **kwargs):
        instance = super(SIMON_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.simon_cipher
