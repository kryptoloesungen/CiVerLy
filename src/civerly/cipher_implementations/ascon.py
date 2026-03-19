from civerly.sboxcipher import SBoxCipher
from civerly.wordsboxcipher import WordSBoxCipher
from civerly.component import SBox_CVL, RoundkeyXOR_CVL, LinearLayer_CVL
from sage.crypto.sboxes import Ascon as ascon_S

from sage.rings.finite_rings.finite_field_constructor import GF
from sage.matrix.special import circulant
from sage.modules.free_module_element import vector


class ASCON_CVL:
    def __init__(self, R=12, name=None):
        r"""
        The CiVerLy implementation of ASCON. It takes the following arguments:

            - ``R`` -- integer; Number of rounds.

            - ``name`` -- string; The name of the cipher (optional).
              Will be used to name the cipher and the corresponding files
              generated (such as the reports and cipher graphs).

        This cipher is "plug-and-play" usable, i.e. it can be directly used
        when imported.

        EXAMPLES::

            sage: from civerly.util import int_to_vec, vec_to_int
            sage: from civerly.cipher_implementations.ascon import ASCON_CVL
            sage: ascon = ASCON_CVL(R=4)
            sage: hex(vec_to_int(ascon(int_to_vec(0x12345678,320))))
            '0xc11ab05dd48d088bb6c89db8226db8c5320a365e071923f271052f313bf57555ec2f2a6f79ca5be0'

        TESTS::

            sage: from civerly.cipher_implementations.ascon import ASCON_CVL
            sage: from civerly.model_options import *
            sage: import tempfile
            sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - cryptominisat  # optional - espresso  # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
            ....:   cipher = ASCON_CVL(R=2)
            ....:   model_options = MODEL_OPTIONS(
            ....:     cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
            ....:     optimization=OPTIMIZATION.SAT,
            ....:     granularity=GRANULARITY.BITWISE,
            ....:     sbox_modeling=SBOX_MODELING.LOGICAL_COND_ESPRESSO,
            ....:     linear_layer_modeling=LINEAR_LAYER_MODELING.EXCLUDE_ODD,
            ....:     sat_solver=CRYPTOMINISAT_CVL(),
            ....:     logic_minimizer=ESPRESSO_CVL(),
            ....:     solve_range=(7, 9),
            ....:     path=Path(tmpdir))
            ....:   cipher.analyse(model_options=model_options)
            ....:   cipher.generate_report(model_options)
            ....:   trail = str(cipher.get_trail(model_options))
            ....:   assert "Unnamed Component" not in trail
            20384 variables and 51649 clauses were written to
            '...'
            [  7 ,  9] (trying w =   8) : SAT
            [  7 ,  8] (trying w =   7) : UNSAT
            8
            Output file in: ...


        """
        if name is None:
            name = "ascon"

        constants = [
            0xf0, 0xe1, 0xd2, 0xc3,
            0xb4, 0xa5, 0x96, 0x87,
            0x78, 0x69, 0x5a, 0x4b
        ]

        s = SBox_CVL(ascon_S, name="SBox")

        sbox_layer = WordSBoxCipher(5, 64, 64, name="sbox_layer")
        for j in range(64):
            node = sbox_layer.add_subcipher(s, [(sbox_layer.IN, (j, 0))])
            sbox_layer.add_output([(node, (0, j))])

        arr = [0 for _ in range(64)]
        arr[0], arr[19], arr[28] = 1, 1, 1
        L1 = circulant(vector(GF(2), arr)).transpose()

        arr = [0 for _ in range(64)]
        arr[0], arr[39], arr[61] = 1, 1, 1
        L2 = circulant(vector(GF(2), arr)).transpose()

        arr = [0 for _ in range(64)]
        arr[0], arr[1], arr[6] = 1, 1, 1
        L3 = circulant(vector(GF(2), arr)).transpose()

        arr = [0 for _ in range(64)]
        arr[0], arr[10], arr[17] = 1, 1, 1
        L4 = circulant(vector(GF(2), arr)).transpose()

        arr = [0 for _ in range(64)]
        arr[0], arr[7], arr[41] = 1, 1, 1
        L5 = circulant(vector(GF(2), arr)).transpose()

        linear_layer = WordSBoxCipher(64, 5, 5, name="linear_layer")
        for j, ll in enumerate([L1, L2, L3, L4, L5]):
            node = linear_layer.add_subcipher(
                LinearLayer_CVL(ll, name=f"LL{j}"), [(linear_layer.IN, (j, 0))]
            )
            linear_layer.add_output([(node, (0, j))])

        # Implementing the key addition
        # ------------------------------------------------ #
        const_add = SBoxCipher(320, 320, name="const_add")
        add = RoundkeyXOR_CVL(8, 0x0, name="add")
        node = const_add.add_subcipher(
            add, [(const_add.IN, (i + 184, i)) for i in range(8)]
        )
        const_add.add_output([(const_add.IN, (i, i)) for i in range(184)])
        const_add.add_output([(node, (i, i + 184)) for i in range(8)])
        const_add.add_output([(const_add.IN, (i, i)) for i in range(192, 320)])
        # ------------------------------------------------ #

        # Implementation of ASCON-round
        ascon_round = SBoxCipher(320, 320, name="ascon_round")
        node = ascon_round.add_subcipher(
            const_add,
            [(ascon_round.IN, (i, i)) for i in range(320)]
        )
        node = ascon_round.add_subcipher(
            sbox_layer,
            [(node, (64*i + j, 5*j + i)) for j in range(64) for i in range(5)]
        )
        node = ascon_round.add_subcipher(
            linear_layer,
            [(node, (5*j + i, 64*i + j)) for j in range(64) for i in range(5)]
        )

        ascon_round.add_output([(node, (i, i)) for i in range(320)])

        # Inserting the round functions into the ASCON cipher
        # ------------------------------------------------ #
        ascon_cipher = SBoxCipher(320, 320, name=name)
        node_round_start = ascon_cipher.IN

        for r in range(R):
            ascon_round.nodes[1].nodes[1].const = constants[-R:][r]
            node_round_start = ascon_cipher.add_subcipher(
                ascon_round, [(node_round_start, (i, i)) for i in range(320)]
            )
        ascon_cipher.add_output(
            [(node_round_start, (i, i)) for i in range(320)]
        )
        # ------------------------------------------------ #

        self.ascon_cipher = ascon_cipher

    def __new__(cls, *args, **kwargs):
        instance = super(ASCON_CVL, cls).__new__(cls)
        instance.__init__(*args, **kwargs)
        return instance.ascon_cipher
