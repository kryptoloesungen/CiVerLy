"""
Encoding specific functions.

Several components have encodings which are similar / identical.
This file groups together functions which are specific to the encoding
of such identical relations.

"""


def _identity_table(width: int) -> tuple[int]:
    return tuple(range(width))


def _rotation_table(width: int, degree: int) -> tuple[int]:
    return tuple(range((-degree) % width, width)) + tuple(range((-degree) % width))
