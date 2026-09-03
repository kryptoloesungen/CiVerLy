from civerly.andrx import AndRX
from civerly.component import (
    AND_CVL,
    ROT_AND_CVL,
    XOR_CVL,
    RotateLayer_CVL,
    RoundkeyXOR_CVL,
)

# Dictionary to determine the number of rounds, based on the cipher parameters.
# Has the form: dictionary[(block_size,key_size)] = R
dictionary = {
    (32, 64): 32,
    (48, 72): 36,
    (48, 96): 36,
    (64, 96): 42,
    (64, 128): 44,
    (96, 96): 52,
    (96, 144): 56,
    (128, 128): 68,
    (128, 192): 69,
    (128, 256): 72,
}


class SIMON_CVL:
    def __init__(
        self,
        block_size,
        key_size,
        R=None,
        key_schedule=None,
        k=None,
        use_rotand=True,
        name=None,
    ):
        r"""
        The CiVerLy implementation of SIMON. It takes the following arguments:

            - ``block_size``-- integer; Determines the block size of the SIMON
              instance. Together with ``key_size``, it determines the
              SIMON-2n-mn instance.

            - ``key_size``-- integer; Determines the key size of the SIMON
              instance. Together with ``block_size``, it determines the
              SIMON-2n-mn instance.

            - ``key_schedule`` -- :class:`civerly.keyschedule.KeySchedule`
              (optional); Key schedule instance used to derive round keys from
              ``k`` via ``set_round_keys``. No built-in key schedule is
              implemented for SIMON; pass a custom ``KeySchedule`` subclass
              instance, or :class:`civerly.keyschedule.DefaultKeySchedule_CVL`
              to pass explicit round keys (``R`` of them, ``n = block_size//2``
              bits each). Defaults to ``None`` (no key schedule, all-zero
              round keys).

            - ``k`` -- integer (optional); The master key passed to
              ``key_schedule``, immediately expanded and injected via
              ``set_round_keys`` when both are given. Has no effect when
              ``key_schedule`` is ``None``.

            - ``name`` -- string (optional); The name of the cipher.
              Will be used to name the cipher and the corresponding files
              generated (such as the reports and cipher graphs).

        This cipher is "plug-and-play" usable, i.e. it can be directly used
        when imported. SIMON can be implemented in two different ways, either
        using separate `RotateLayer_CVL` and `AND_CVL` components, or by
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
            sage: from civerly.keyschedule import DefaultKeySchedule_CVL
            sage: P = 0x6f7220676e696c63
            sage: k = 0x30201000b0a090813121110ffae9dcec4facc91c83d1bb6b5d510ff36e2c07c727090431343f40eea417e409e635793a69654788b052e75884c5f47d0e4e598e3e8036335f020e11afa1c76bee71ed6763d4d2a0ca19efc0046cb1b59ce07043dfb4191cbd9e8ccf3f75b6da34520b7ba7ae12d60e056a6f6a8d0f4943a89c1b4db50fe3481f018ee1d573f4806d09756feb8ff0e529452d6d654a47eb6e8dd8990d838b082bddc
            sage: C = 0x5ca2e27f111a8fc8
            sage: V, W = 64, 96
            sage: simon_cipher = SIMON_CVL(V, W, k=k, key_schedule=DefaultKeySchedule_CVL(32, 42))
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
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     solve_range=(16, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            4160 variables and 8641 clauses were written to '...'
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
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     solve_range=(16, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            3912 variables and 9041 clauses were written to '...'
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
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     solve_range=(16, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            4160 variables and 8641 clauses were written to '...'
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
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     solve_range=(16, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            3912 variables and 9041 clauses were written to '...'
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
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     solve_range=(10, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            5648 variables and 13169 clauses were written to '...'
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
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     solve_range=(10, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            6000 variables and 12817 clauses were written to '...'
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
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     solve_range=(10, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            5648 variables and 13169 clauses were written to '...'
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
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     logic_minimizer=SOLVER.ESPRESSO,
            ....:     solve_range=(10, 20),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            6000 variables and 12817 clauses were written to '...'
            15
        """
        if name is None:
            name = "simon"

        n = int(block_size // 2)
        if R is None:
            R = dictionary[(block_size, key_size)]
        rks = [0] * R

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
            node_rot1 = simon_round.add_subcipher(rot1, [(simon_round.IN, (0, 0))])
            node_rot8 = simon_round.add_subcipher(rot8, [(simon_round.IN, (0, 0))])
            node_and = simon_round.add_subcipher(
                and1, [(node_rot1, (0, 0)), (node_rot8, (0, 1))]
            )
            node_xor1 = simon_round.add_subcipher(
                xor, [(node_and, (0, 0)), (simon_round.IN, (1, 1))]
            )
        else:  # insert ROT_AND_CVL component
            node_rot1 = simon_round.add_subcipher(rot1, [(simon_round.IN, (0, 0))])
            node_rot_and = simon_round.add_subcipher(ra1, [(node_rot1, (0, 0))])
            node_xor1 = simon_round.add_subcipher(
                xor, [(node_rot_and, (0, 0)), (simon_round.IN, (1, 1))]
            )

        node_rot2 = simon_round.add_subcipher(rot2, [(simon_round.IN, (0, 0))])
        node_xor2 = simon_round.add_subcipher(
            xor, [(node_xor1, (0, 0)), (node_rot2, (0, 1))]
        )
        node_keyxor = simon_round.add_subcipher(key_add, [(node_xor2, (0, 0))])
        simon_round.add_output([(node_keyxor, (0, 0)), (simon_round.IN, (0, 1))])
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
            simon_cipher.nodes[r + 1].nodes[node_keyxor] for r in range(R)
        ]
        simon_cipher.key_schedule = key_schedule
        if key_schedule is not None and k is not None:
            simon_cipher.set_round_keys(k)

        self.simon_cipher = simon_cipher

    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.simon_cipher
