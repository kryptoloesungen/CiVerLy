r"""
Implementation of the ``AESlike`` subclass of ``Cipher``.

The AESlike class assumes a rectangular state matrix of
:math:`n \times m` words of size :math:`w`. This state will be transformed by
the wordwise application of the same w-bit SBox in parallel (called an
SBox-layer), a wordwise permutation (called PermuteState), and a column-wise
application of a linear layer (called a MixColumn operation), which possibly
but not necessarily might be described as an operation over
:math:`\mathbb{F}_{2^w}` . Finally, a sub-cipher describing the round key
addition is allowed to be inserted into an AESlike cipher as well. Due to these
strict specifications, it is possible to apply a number of modeling techniques
to generate MILP/SAT models, since each of the methods possible for any super-
class of AESlike is applicable here as well. Examples for ciphers that can be
implemented as AESlike instances are AES, SKINNY, MIDORI and CRAFT.


EXAMPLES::

    sage: from sage.crypto.sboxes import PRESENT
    sage: from civerly.util import int_to_vec, vec_to_int
    sage: from civerly.component import SBox_CVL, ModAdd_CVL, LinearLayer_CVL
    sage: from civerly.aeslike import AESlike
    sage: aeslikecipher = AESlike(4, 5, 3, "Cipher") # 5 rows x 3 columns
    sage: modadd = ModAdd_CVL(4)
    sage: edges = [(aeslikecipher.IN, (0, 0)), (aeslikecipher.IN, (1, 0))]
    sage: aeslikecipher.add_subcipher(modadd, edges)
    Traceback (most recent call last):
    ...
    TypeError: The passed sub_cipher has type <class 'civerly.component.ModAdd_CVL'> and is not allowed in SBoxCiphers.
    sage: sb = SBox_CVL(PRESENT)
    sage: for i in range(15):
    ....:   edges = [(aeslikecipher.IN, (i, 0))]
    ....:   node = aeslikecipher.add_subcipher(sb, edges)
    ....:   aeslikecipher.add_output([(node, (0, i))])
"""

from civerly.wordsboxcipher import WordSBoxCipher
from civerly.component import LinearLayer_CVL


class AESlike(WordSBoxCipher):
    def __init__(self, wordsize, rows, cols, name) -> None:
        r"""
        AESlike:

        The counting in AESlike is column by column, i.e.

            +---+----+----+-----+
            | 0 |  4 |  8 |  12 |
            +---+----+----+-----+
            | 1 |  5 |  9 |  13 |
            +---+----+----+-----+
            | 2 |  6 |  10|  14 |
            +---+----+----+-----+
            | 3 |  7 |  11|  15 |
            +---+----+----+-----+

        INPUT::

            - ``num_rows`` -- integer; Specifies the number of rows in the
              AES-like state matrix.

            - ``num_cols`` -- integer; Specifies the number of columns in the
              AES-like state matrix.

            - ``wordsize`` -- integer; Specifies the wordsize in number of
              bits, i.e. the size of each entry in the state matrix.

        OUTPUT:: An AESlike instance.

        TESTS::

            sage: from civerly.aeslike import AESlike
            sage: cipher = AESlike(9, 2, 4, name="aeslike")
            sage: cipher
            aeslike: 72 -> 72 bits
                Sub ciphers:

        .. SEEALSO::

            - ``Cipher.__init__`` for the initialization details.
        """
        self.__rows = rows
        self.__cols = cols
        super().__init__(
            wordsize, self.rows * self.cols, self.rows * self.cols, name=name
        )

    def add_subcipher(self, sub_cipher, edges):
        r"""
        .. SEEALSO::

            - ``Cipher.add_subcipher``
        """
        if type(sub_cipher) is LinearLayer_CVL:
            # this means LinearLayer, but not PermuteLayer or RotateLayer
            if not sub_cipher.input_length == self.rows * self.wordsize:
                a = self.rows * self.wordsize
                b = sub_cipher.input_length
                e = "LinearLayer should be MixColumn and should be of size "
                e += f"{a} instead of {b}!"
                raise AssertionError(e)
            minimum = min([e[1][1] for e in edges])
            maximum = max([e[1][1] for e in edges]) - minimum
            if not (
                (maximum - minimum == self.rows - 1) and (minimum % self.rows == 0)
            ):
                e = "Only properly aligned MixColumn allowed!"
                raise AssertionError(e)

        return super().add_subcipher(sub_cipher, edges)

    @property
    def rows(self):
        r"""
        Return the number of rows of ``self``.

        TESTS::

            sage: from civerly.aeslike import AESlike
            sage: cipher = AESlike(9, 2, 4, name="aeslike")
            sage: cipher.rows
            2

        """
        assert self.__rows > 0
        return int(self.__rows)

    @property
    def cols(self):
        r"""
        Return the number of columns of ``self``.

        TESTS::

            sage: from civerly.aeslike import AESlike
            sage: cipher = AESlike(9, 2, 4, name="aeslike")
            sage: cipher.cols
            4

        """
        assert self.__cols > 0
        return int(self.__cols)

    def _to_dict(self):
        d = super()._to_dict()
        d["type"] = "AESlike"
        d["rows"] = self.rows
        d["cols"] = self.cols
        return d

    @classmethod
    def _init_from_dict(cls, d):
        return cls(d["wordsize"], d["rows"], d["cols"], name=d["name"])
