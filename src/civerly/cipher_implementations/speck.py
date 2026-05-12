from civerly.addrx import AddRX
from civerly.component import ModAdd_CVL, XOR_CVL, RotateLayer_CVL, ConstXOR_CVL
from civerly.component import RoundkeyXOR_CVL
from civerly.keyschedule import KeySchedule

# Dictionary to determine the number of rounds, based on the cipher parameters.
# Has the form: dictionary[(block_size,key_size)] = R
dictionary = {
    (32, 64): 22, (48, 72): 22, (48, 96): 23, (64, 96): 26, (64, 128): 27,
    (96, 96): 28, (96, 144): 29, (128, 128): 32, (128, 192): 33, (128, 256): 34
}


def _make_speck_ks_step(n, alpha, beta, round_idx):
    """One SPECK key-schedule step as an AddRX cipher.

    Input: word 0 = l_i, word 1 = k_i.
    Output: word 0 = l_{i+m-1}, word 1 = k_{i+1}.

        l_{i+m-1} = (ROR_alpha(l_i) + k_i) XOR round_idx
        k_{i+1}   = ROL_beta(k_i) XOR l_{i+m-1}
    """
    step = AddRX(n, 2, 2, name=f"KS-step-{round_idx}")

    # ROR_alpha on l_i (word 0)
    node_rot_l = step.add_subcipher(
        RotateLayer_CVL(n, -alpha, name="ROR_alpha"),
        [(step.IN, (0, 0))],
    )
    # ModAdd: ROR_alpha(l_i) [word 0] + k_i [word 1]
    node_add = step.add_subcipher(
        ModAdd_CVL(n, name="ModAdd"),
        [(node_rot_l, (0, 0)), (step.IN, (1, 1))],
    )
    # XOR with round index → l_{i+m-1}
    node_l_new = step.add_subcipher(
        ConstXOR_CVL(n, round_idx, name="XOR_rnd"),
        [(node_add, (0, 0))],
    )
    # ROL_beta on k_i (word 1 → word 0)
    node_rot_k = step.add_subcipher(
        RotateLayer_CVL(n, beta, name="ROL_beta"),
        [(step.IN, (1, 0))],
    )
    # XOR: ROL_beta(k_i) [word 0] ⊕ l_{i+m-1} [word 1] → k_{i+1}
    node_k_new = step.add_subcipher(
        XOR_CVL(n, name="XOR_k"),
        [(node_rot_k, (0, 0)), (node_l_new, (0, 1))],
    )
    step.add_output(
        [(node_l_new, (0, 0)), (node_k_new, (0, 1))],
    )
    return step


class SPECK_KeySchedule_CVL(KeySchedule):
    def __init__(self, block_size, key_size, R=None):
        r"""
        SPECK-2n/mn key schedule as a CiVerLy DAG.

        Takes an ``mn``-bit master key and expands it into ``R`` round keys of
        ``n`` bits each, following the SPECK key schedule specification.

        INPUT:

            - ``block_size`` -- integer; block size of the SPECK instance (2n).

            - ``key_size`` -- integer; key size of the SPECK instance (mn).

            - ``R`` -- integer (optional); number of rounds. Defaults to the
              standard number of rounds for the given parameter set.

        EXAMPLES::

            sage: from civerly.cipher_implementations.speck import SPECK_KeySchedule_CVL
            sage: ks = SPECK_KeySchedule_CVL(64, 96)
            sage: rks = ks(0x131211100b0a090803020100)
            sage: hex(rks[0])
            '0x3020100'
            sage: hex(rks[1])
            '0x131d0309'
            sage: hex(rks[2])
            '0xbbd80d53'

        TESTS:

        Full key schedule for SPECK-64/96 against the test vector in the
        SPECK specification (key ``131211100b0a090803020100``)::

            sage: from civerly.cipher_implementations.speck import SPECK_KeySchedule_CVL
            sage: ks = SPECK_KeySchedule_CVL(64, 96)
            sage: rks = ks(0x131211100b0a090803020100)
            sage: rks == [
            ....:   0x03020100, 0x131d0309, 0xbbd80d53, 0x1a2370c1, 0xe45d26dd,
            ....:   0x63cb3f1c, 0x27597d5a, 0x205175b4, 0xdb01db9f, 0x9812aac8,
            ....:   0x16796373, 0xff72647b, 0xccda7364, 0xd6f4b7c9, 0x2589bf5a,
            ....:   0x39741c59, 0x85a6aa9c, 0x208eb076, 0x71a9351e, 0x8eff59e3,
            ....:   0x498ff996, 0x15ec7c21, 0x0f49104a, 0xd8ea21bc, 0xdcdb415c,
            ....:   0x2fa7e901,
            ....: ]
            True

        Verify end-to-end encryption via ``set_master_key`` for SPECK-64/96::

            sage: from civerly.cipher_implementations.speck import SPECK_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: speck = SPECK_CVL(64, 96)
            sage: speck.set_master_key(0x131211100b0a090803020100)
            sage: vec_to_int(speck(int_to_vec(0x74614620736e6165, 64))) == \
            ....:   0x9f7952ec4175946c
            True

        SPECK-32/64 key schedule (special case: alpha=7, beta=2, m=4).
        Key ``1918 1110 0908 0100`` from the SPECK specification::

            sage: from civerly.cipher_implementations.speck import SPECK_KeySchedule_CVL
            sage: ks = SPECK_KeySchedule_CVL(32, 64)
            sage: ks(0x1918111009080100) == [
            ....:   0x0100, 0x1512, 0x617d, 0x1458, 0x6919, 0x77e2,
            ....:   0x0c89, 0xccdb, 0xefea, 0x4e33, 0x76f4, 0x5976,
            ....:   0xee8b, 0xdb04, 0x4617, 0xf37e, 0x87b4, 0x8eca,
            ....:   0xed9b, 0x3a52, 0x8229, 0xed64,
            ....: ]
            True

        SPECK-128/128 end-to-end test vector from the SPECK specification::

            sage: from civerly.cipher_implementations.speck import SPECK_CVL
            sage: from civerly.util import int_to_vec, vec_to_int
            sage: speck = SPECK_CVL(128, 128)
            sage: speck.set_master_key(0x0f0e0d0c0b0a09080706050403020100)
            sage: pt = int_to_vec(0x6c617669757165207469206564616d20, 128)
            sage: vec_to_int(speck(pt)) == 0xa65d9851797832657860fedf5c570d18
            True

        """
        if (block_size, key_size) == (32, 64):
            alpha, beta = 7, 2
        else:
            alpha, beta = 8, 3

        n = block_size // 2
        m = key_size // n
        if R is None:
            R = dictionary[(block_size, key_size)]

        super().__init__(key_size, R * n, name=f"SPECK-{block_size}/{key_size}-KeySchedule")

        # Master key layout (MSB first): l_{m-2} | ... | l_0 | k_0
        # l_j is at IN bits (m-2-j)*n .. (m-1-j)*n - 1  (for j = 0 .. m-2)
        # k_0 is at IN bits (m-1)*n .. m*n - 1
        #
        # Each step j produces l_{j+m-1} at output bits 0..n-1
        #                  and k_{j+1}   at output bits n..2n-1.
        # We need R-1 steps to produce k_1 .. k_{R-1}.

        step_nodes = []

        # k_0 is emitted directly from the master key input.
        output_edges = [(self.IN, ((m - 1) * n + i, i)) for i in range(n)]

        for step_idx in range(R - 1):
            if step_idx < m - 1:
                l_src, l_off = self.IN, (m - 2 - step_idx) * n
            else:
                l_src, l_off = step_nodes[step_idx - (m - 1)], 0

            if step_idx == 0:
                k_src, k_off = self.IN, (m - 1) * n
            else:
                k_src, k_off = step_nodes[step_idx - 1], n

            node = self.add_subcipher(
                _make_speck_ks_step(n, alpha, beta, step_idx),
                [(l_src, (l_off + i, i)) for i in range(n)]
                + [(k_src, (k_off + i, n + i)) for i in range(n)],
            )
            step_nodes.append(node)
            output_edges += [(node, (n + i, (step_idx + 1) * n + i)) for i in range(n)]

        self.add_output(output_edges)
        self._n = n
        self._R = R

    def __call__(self, k):
        r"""
        Expand master key ``k`` into a list of ``R`` round-key integers.

        INPUT:

            - ``k`` -- integer; master key.

        OUTPUT: List of ``R`` integers, one per round.
        """
        from civerly.util import int_to_vec, vec_to_int
        bits = self.eval(int_to_vec(k, self.input_length))
        n = self._n
        return [vec_to_int(bits[i * n:(i + 1) * n]) for i in range(self._R)]


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
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            1788 variables and 4189 clauses were written to '...'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 ,  6] (trying w =   3) : UNSAT
            [  4 ,  6] (trying w =   5) : SAT
            [  4 ,  5] (trying w =   4) : UNSAT
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
            ....:     sat_solver=CADICAL_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            1788 variables and 4189 clauses were written to '...'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 ,  6] (trying w =   3) : UNSAT
            [  4 ,  6] (trying w =   5) : SAT
            [  4 ,  5] (trying w =   4) : UNSAT
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
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            2992 variables and 7776 clauses were written to '...'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : UNSAT
            [  7 , 12] (trying w =   9) : SAT
            [  7 ,  9] (trying w =   8) : UNSAT
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
            ....:     sat_solver=CADICAL_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            2992 variables and 7776 clauses were written to '...'
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : UNSAT
            [  7 , 12] (trying w =   9) : SAT
            [  7 ,  9] (trying w =   8) : UNSAT
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
            ....:     sat_solver=CADICAL_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     number_of_solutions=5,
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            1392 variables and 3516 clauses were written to ...
            [  0 ,100] (trying w =  50) : SAT
            [  0 , 50] (trying w =  25) : SAT
            [  0 , 25] (trying w =  12) : SAT
            [  0 , 12] (trying w =   6) : SAT
            [  0 ,  6] (trying w =   3) : SAT
            [  0 ,  3] (trying w =   1) : SAT
            [  0 ,  1] (trying w =   0) : UNSAT
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

        # Collect references to all RoundkeyXOR_CVL components for key schedule
        # support. Each entry points to the KeyAdd component inside the
        # corresponding round node. Set key_schedule to a callable returning
        # R round keys to enable set_master_key(k).
        # -------------------------------------------------------- #
        speck_cipher._rk_components = [
            speck_cipher.nodes[r+1].nodes[node_after_keyadd] for r in range(R)
        ]
        speck_cipher.key_schedule = SPECK_KeySchedule_CVL(block_size, key_size, R)

        self.speck_cipher = speck_cipher

    def __new__(cls, *args, **kwargs):
        instance = super(SPECK_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.speck_cipher
