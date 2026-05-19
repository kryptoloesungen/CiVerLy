from civerly.addrx import AddRX
from civerly.component import ModAdd_CVL, XOR_CVL, RotateLayer_CVL
from civerly.component import RoundkeyXOR_CVL

# Dictionary to determine the number of rounds, based on the cipher parameters.
# Has the form: dictionary[(block_size,key_size)] = R
dictionary = {
    (32, 64): 22, (48, 72): 22, (48, 96): 23, (64, 96): 26, (64, 128): 27,
    (96, 96): 28, (96, 144): 29, (128, 128): 32, (128, 192): 33, (128, 256): 34
}


class SPECK_CVL:
    def __init__(self, block_size, key_size, R=None, rks=[], name=None):
        r"""
        The CiVerLy implementation of SPECK. It takes the following arguments:

            - ``block_size``-- integer; Determines the block size of the SPECK
              instance. Together with ``key_size``, it determines the
              SPECK-2n-mn instance

            - ``key_size``-- integer; Determines the key size of the SPECK
              instance. Together with ``block_size``, it determines the
              SPECK-2n-mn instance

            - ``rks`` -- list (optional); Specifies the roundkey values of
              SPECK, in order to being able to properly test the
              implementation. Is required to have length ``R+1``, and defaults
              to [0, ..., 0].

            - ``name`` -- string (optional); The name of the cipher.
              Will be used to name the cipher and the corresponding files
              generated (such as the reports and cipher graphs).

        This cipher is "plug-and-play" usable, i.e. it can be directly used
        when imported.

        EXAMPLES::

            sage: from civerly.util import vec_to_int, int_to_vec
            sage: from civerly.cipher_implementations.speck import SPECK_CVL
            sage: speck_cipher = SPECK_CVL(96, 144)
            sage: hex(vec_to_int(speck_cipher(int_to_vec(0xabcd1234, 96))))
            '0xef12cffdd86766108a1af809'


        TESTS::

            sage: from civerly.util import vec_to_int, int_to_vec
            sage: from civerly.cipher_implementations.speck import SPECK_CVL
            sage: P = 0x74614620736e6165
            sage: rks = [
            ....:   0x03020100, 0x131d0309, 0xbbd80d53, 0x1a2370c1, 0xe45d26dd,
            ....:   0x63cb3f1c, 0x27597d5a, 0x205175b4, 0xdb01db9f, 0x9812aac8,
            ....:   0x16796373, 0xff72647b, 0xccda7364, 0xd6f4b7c9, 0x2589bf5a,
            ....:   0x39741c59, 0x85a6aa9c, 0x208eb076, 0x71a9351e, 0x8eff59e3,
            ....:   0x498ff996, 0x15ec7c21, 0x0f49104a, 0xd8ea21bc, 0xdcdb415c,
            ....:   0x2fa7e901
            ....: ]
            sage: C = 0x9f7952ec4175946c
            sage: V, W = 64, 96
            sage: speck_cipher = SPECK_CVL(V, W, rks=rks)
            sage: vec_to_int(speck_cipher(int_to_vec(P, V))) == C
            True

            sage: from civerly.cipher_implementations.speck import SPECK_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
            ....:   cipher = SPECK_CVL(32, 64, R=4)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            1788 variables and 4189 clauses were written to '...'
            5
            Output file in: ...

            sage: from civerly.cipher_implementations.speck import SPECK_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cadical
            ....:   cipher = SPECK_CVL(32, 64, R=4)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            1788 variables and 4189 clauses were written to '...'
            5
            Output file in: ...

        Linear cryptanalysis (the results were tested until :math:`R = 12`
        and match Table 2 in [LWR16])::

            sage: from civerly.cipher_implementations.speck import SPECK_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat
            ....:   cipher = SPECK_CVL(32, 64, R=7)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CRYPTOMINISAT,
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            2992 variables and 7776 clauses were written to '...'
            9
            Output file in: ...

            sage: from civerly.cipher_implementations.speck import SPECK_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cadical
            ....:   cipher = SPECK_CVL(32, 64, R=7)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            2992 variables and 7776 clauses were written to '...'
            9
            Output file in: ...

        Find multiple solutions in SPECK:

            sage: from civerly.cipher_implementations.speck import SPECK_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cadical
            ....:   cipher = SPECK_CVL(32, 64, R=3)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.LINEAR,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     sat_solver=SOLVER.CADICAL,
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     number_of_solutions=5,
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            1392 variables and 3516 clauses were written to ...
            [1, 1, 1, 2, 2]

        """
        if name is None:
            name = "speck"

        # Determine the cipher parameters alpha, beta, n, R
        # -------------------------------------------------------- #
        if (block_size, key_size) == (32, 64):
            alpha = 7
            beta = 2
        else:
            alpha = 8
            beta = 3

        n = int(block_size//2)
        if R is None:
            # use default no. of rounds
            R = dictionary[(block_size, key_size)]
        # -------------------------------------------------------- #
        # roundkeys are defaulted to 0
        if rks == []:
            rks = [0 for _ in range(R+1)]

        # Initialization of the components
        # -------------------------------------------------------- #
        # SPECK is an AddRX cipher, since its non-linear component
        # is modular addition.
        speck_round = AddRX(n, 2, 2, name="speck_round")

        rot_minus_alpha = RotateLayer_CVL(n, -alpha, name="rotate_minus_alpha")
        rot_beta = RotateLayer_CVL(n, beta, name="rotate_beta")
        modadd = ModAdd_CVL(n, name="ModAdd")
        xor = XOR_CVL(n, name="xor")

        # Implement the SPECK round function
        # -------------------------------------------------------- #
        node_rotalpha = speck_round.add_subcipher(
            rot_minus_alpha, [(speck_round.IN, (0, 0))]
        )
        node_modadd = speck_round.add_subcipher(
            modadd, [(node_rotalpha, (0, 0)), (speck_round.IN, (1, 1))]
        )

        keyadd = RoundkeyXOR_CVL(n, 0x0, name="keyadd")
        node_after_keyadd = speck_round.add_subcipher(
            keyadd, [(node_modadd, (0, 0))]
        )

        node_rotbeta = speck_round.add_subcipher(
            rot_beta, [(speck_round.IN, (1, 0))]
        )
        node_xor2 = speck_round.add_subcipher(
            xor, [(node_rotbeta, (0, 0)), (node_after_keyadd, (0, 1))]
        )

        speck_round.add_output(
            [(node_after_keyadd, (0, 0)), (node_xor2, (0, 1))]
        )
        # -------------------------------------------------------- #

        # Adding SPECK rounds into the cipher
        # -------------------------------------------------------- #
        speck_cipher = AddRX(n, 2, 2, name=name)

        node = speck_cipher.IN
        for r in range(R):
            speck_round.nodes[node_after_keyadd].const = rks[r]
            node = speck_cipher.add_subcipher(
                speck_round, [(node, (0, 0)), (node, (1, 1))]
            )
        speck_cipher.add_output([(node, (0, 0)), (node, (1, 1))])
        # -------------------------------------------------------- #

        self.speck_cipher = speck_cipher

    def __new__(cls, *args, **kwargs):
        instance = super(SPECK_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.speck_cipher
