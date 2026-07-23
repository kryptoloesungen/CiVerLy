import ctypes
from pathlib import Path


def get_inequations(ddt, fixed_probability=None) -> list:
    r"""
    Generated inequations to model s-box transitions as proposed by Boura &
    Coggia in (https://doi.org/10.13154/tosc.v2020.i3.327-361). It takes the
    following arguments:

        - ``ddt`` -- Matrix_integer_dense; DDT/LAT as returned by
          sage.crypto.sbox

        - ``fixed_probability`` -- (optional) integer; If set,
          only transitions that happen with this probability are seen
          to be possible

    EXAMPLES:

        Encrypt a message (for verifying the implemenation)::

            sage: from civerly.distorted_balls import distorted_balls
            sage: from sage.crypto.sboxes import PRESENT as PRESENT_S_sage
            sage: ddt = PRESENT_S_sage.difference_distribution_table()
            sage: ineq = distorted_balls.get_inequations(ddt)
            sage: len(ineq)
            708
            sage: ineq[-1]
            [-5, -4, 6, -4, -6, -6, -1, -2, -22]


    TESTS:

        Test inequations for PRESENT (all probabilities)::

            sage: from civerly.distorted_balls import distorted_balls
            sage: from sage.crypto.sboxes import PRESENT as PRESENT_S_sage
            sage: ddt = PRESENT_S_sage.difference_distribution_table()
            sage: ineq = distorted_balls.get_inequations(ddt)
            sage: len(ineq)
            708
            sage: distorted_balls.verify_inequations(ineq, ddt, None)
            True

        Test inequations for PRESENT (transitions with probability 2 only)::

            sage: from civerly.distorted_balls import distorted_balls
            sage: from sage.crypto.sboxes import PRESENT as PRESENT_S_sage
            sage: ddt = PRESENT_S_sage.difference_distribution_table()
            sage: ineq = distorted_balls.get_inequations(ddt, 2)
            sage: len(ineq)
            1151
            sage: distorted_balls.verify_inequations(ineq, ddt, 2)
            True
    """
    # Shared library responsible for computing the inequations
    pkg_dir = Path(__file__).parent.parent
    lib_path = next(pkg_dir.glob("distorted_balls*.so"))
    lib = ctypes.CDLL(lib_path)

    lib.compute_inequations.argtypes = [
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_int,
    ]

    # The equations are returned in a two-dimensional array
    lib.compute_inequations.restype = ctypes.POINTER(ctypes.POINTER(ctypes.c_int8))

    n_input = ddt.nrows()
    n_output = ddt.ncols()
    input_size = n_input.bit_length() - 1
    output_size = n_output.bit_length() - 1
    total_size = input_size + output_size
    if fixed_probability is None:
        possible_points = [
            (b << input_size) | a
            for a in range(n_input)
            for b in range(n_output)
            if ddt[a][b] != 0
        ]
    else:
        possible_points = [
            (b << input_size) | a
            for a in range(n_input)
            for b in range(n_output)
            if ddt[a][b] == fixed_probability
        ]

    output = lib.compute_inequations(
        total_size,
        (ctypes.c_uint32 * len(possible_points))(*possible_points),
        len(possible_points),
    )  # Call library to compute the inequations
    assert output, f"ERROR: Got no output from {lib_path}->compute_inequations()"
    # 'output' is a pointer to an array of pointers, which we will convert to
    # a two-dimensional list 'inequations'
    inequations = []
    cnt = 0
    while True:
        inequation = list(output[cnt][: total_size + 1])
        # If all entries are zero, we are at the end of the outer array
        if not any(inequation):
            break
        inequations.append(
            inequation[:input_size][::-1]
            + inequation[input_size : input_size + output_size][::-1]
            + inequation[input_size + output_size :]
        )  # Change bit order to comply with s-box evaluation
        cnt += 1

    return inequations


def verify_inequations(inequations, ddt, fixed_probability=None):
    r"""
    Verifies that the inequations correctly model the transitions given
    by the DDT/LAT

        - ``inequations`` -- [[integer]]; List of inequations, each
          represented as a list of coefficients

        - ``ddt`` -- Matrix_integer_dense;
          DDT/LAT as returned by sage.crypto.sbox

        - ``fixed_probability`` -- (optional) integer; If set, only
          transitions that happen with this probability are seen to be possible

    """
    input_size = ddt.nrows().bit_length() - 1
    output_size = ddt.ncols().bit_length() - 1

    if fixed_probability is None:

        def _is_possible_ddt(prob):
            return prob != 0
    else:

        def _is_possible_ddt(prob):
            return prob == fixed_probability

    def _is_possible_inequations(input_difference, output_difference):
        r"""
        Checks if (input_difference, output_difference) verify all inequations
        """
        for ineq in inequations:
            res = 0
            for i in range(input_size):
                # the 0-th bit is the msb
                res += ((input_difference >> i) & 1) * ineq[input_size - i - 1]
            for i in range(output_size):
                # the 0-th bit is the msb
                res += ((output_difference >> i) & 1) * ineq[
                    input_size + output_size - i - 1
                ]
            if res < ineq[input_size + output_size]:
                return False
        return True

    for in_diff, row in enumerate(ddt):
        for out_diff, prob in enumerate(row):
            if _is_possible_ddt(prob) != _is_possible_inequations(in_diff, out_diff):
                return False
    return True
