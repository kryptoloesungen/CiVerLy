================
Developer Manual
================

CiVerLy is implemented as a Python package extending the computer algebra system SageMath, which we often refer to as ``sage``.
As such, it can be installed using the Python package manager ``pip``, which comes with ``sage``, from the provided source files.
Notice that this installation does not inherently require an internet connection, as ``pip`` can be instructed to work offline.
Of course, the source code of CiVerLy as well as the optional but highly recommended external dependencies such as the Espresso minimizer or the MILP and SAT solvers must be obtained somehow which usually involves an internet connection.

.. toctree::
   :hidden:
   :maxdepth: 1

   file_structure
   nix
   building_docs
   tests
