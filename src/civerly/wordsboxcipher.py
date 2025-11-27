r"""
The ``WordSBoxCipher`` class. Inherits its main functionalities from
``WordBasedCipher`` and ``SBoxCipher``.

A ``WordSBoxCipher`` combines both functionalities of its parent classes:
Any component should have a ``input_length`` and ``output_length`` that
is a multiple of ``self.wordsize``, and is not allowed to be of type
``ModAdd_CVL`` nor ``AND_CVL``.

The main purpose of this class is to support word-wise MILP modeling.
This is possible because next to the fixed word size,
it is ensured that the ciphers non-linear part comprises only of ``SBox_CVL``,
which can be modeled using MILP.
"""

from civerly.wordbasedcipher import WordBasedCipher
from civerly.sboxcipher import SBoxCipher


class WordSBoxCipher(WordBasedCipher, SBoxCipher):
    pass
