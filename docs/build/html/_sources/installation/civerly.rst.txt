========================
Installation of CiVerLy
========================

Make sure that the CiVerLy environment, especially SageMath, is set up as
described before.
As all dependencies of CiVerLy are already installed within SageMath, which can be verified by running

.. code-block:: console

   $ sage --python -m pip list packages

and making sure that ``setuptools`` and ``wheel`` are in the list, an
installation without internet connection is no problem.
Install CiVerLy by running:

.. code-block:: console

   $ make
   $ sage --python -m pip install --no-index --no-build-isolation .

The ``--no-index`` flag will stop ``pip`` from trying to search for the
dependencies online and the ``--no-build-isolation`` flag allows ``pip`` to use
the already installed versions of the dependencies.

Testing CiVerLy (Optional)
===========================

To run the tests, change to the packages root directory ``civerly`` and
run the following command, but **remove solvers that are not installed**:

.. code-block:: console

   $ sage -t --optional=sage,scip,glpk,gurobi,cryptominisat,cadical,espresso src/civerly

.. warning::
   The doctests temporarily add and remove files while testing.
   Therefore it is advised to not run several doctests simultaneously, in order to avoid concurrency issues!
