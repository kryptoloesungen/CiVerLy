r"""
This file contains implementations of several toy ciphers that aim to cover as
many edge cases for CiVerLy as possible. Currently, there are nine toy
ciphers,
each with their own unusual feature:

    - :class:`Toy1` -- linear cipher with non-bijective :class:`LinearLayer_CVL`
      and different intermediate state sizes and direct in- out- connection
    - :class:`Toy2` -- linear cipher using rounds with intentionally missing
      structure of each layer
    - :class:`Toy3` -- sbox cipher with missing structure of each layer
    - :class:`Toy4` -- linear cipher with :class:`XOR_CVL` component
    - :class:`Toy5` -- cipher using cascade of :class:`Toy3` and :class:`Toy4`
    - :class:`Toy6` -- cipher using :class:`ModAdd_CVL`, enforcing
      probabilistic transition
    - :class:`Toy7` -- cipher using different sbox sizes in one layer
    - :class:`Toy8` -- cipher used to cover that the report generation of C_CVL
      works correctly
    - :class:`Toy9` -- cipher using sboxes with transition of non-integer
      weight
    - :class:`Toy10` -- cipher testing whether linear modeling is the same for
      the following cases:
        - Either, when a normal 6 -> 6 linear layer is used
        - or when that linear layer is separately defined by its coordinate
          functions which are 6 -> 1 and therefore non-bijective.
    - :class:`Toy11` -- cipher testing whether linear modeling of
      :math:`k`-branching works for :math:`k > 2`

"""
