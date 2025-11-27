===============
Automated Tests
===============

Naturally, we also implemented automated testing which is a indispensable foothold of modern software development.
On the one hand, these ensure that our models actually lead to the correct results.
On the other hand, they also make it easy to detect if further additions to the CiVerLy code break any functionality that was working correctly before.
Again, we mimic what sage does.
That is, the aforementioned docstrings can contain ``EXAMPLES`` and ``TESTS`` blocks.
These are made up of ``sage`` commands and their expected outputs.
This already is quite a useful addition to the documentation as examples often deepen the understanding of a function but ``sage`` can also automatically evaluate all those examples and verify that the computed output is indeed the output that was put in the docstring.

Tests involving external dependencies
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For obvious reasons, our tests must involve external tools like MILP and SAT solvers.
This however comes with some pitfalls.
For instance, consider a developer that wants to run all CiVerLy tests but who has not installed all solvers used by CiVerLy.
Luckily, ``sage`` provides a solution for this as test can be marked as optional.
The implementations of ciphers in CiVerLy commonly feature tests like the following.

.. code-block:: sage

   sage: aes.analyse(model_options) # optional - glpk

This test is then only run when the ``sage -t`` invocation contains the optional ``glpk`` flag.
This in turn introduces a new pitfall.
A developer that forgets to put this optional flag will not notice that it is missing if the solver is installed.
This then makes the test fail for other developers that do not have the solver installed.
To prevent this scenario, we added some functionality to CiVerLy that can detect such missing optional flags.
In a nutshell, before invoking a solver CiVerLy checks if this solver was marked as disabled in a Linux environment variable.
If this is the case, CiVerLy stops with an error.
More concretely,

.. code-block:: console

   env CIVERLY_DISABLE_GUROBI=1 sage -t --optional=sage,scip,glpk,cryptominisat,cadical,espresso civerly/src/civerly

will run all tests in CiVerLy except for those that require Gurobi.
If the tests invoke Gurobi anyway, CiVerLy will stop with an error.


Running tests
^^^^^^^^^^^^^

As the example above already shows, tests are executed using ``sage -t``.
Extensive documentation for the ``sage`` doctesting framework is available `online <https://doc.sagemath.org/html/en/developer/doctesting.html>`_.
Here, we want to highlight some useful options.
First, we can mark doctests that will take long time as follows:

.. code-block:: sage

   sage: present_cipher.analyse(model_options) # long

To include these when running the tests, add ``--long`` to the ``sage -t`` command.

Further, ``sage`` can run tests in parallel.
To do so, add for instance ``--nthreads=8`` to the ``sage -t`` command.
When doing so, ensure that the different tests do not access the same files.

Another useful flag is ``--exitfirst`` which will stop all tests as soon as one failed.
Use ``--logfile=filename.log`` to write a log file.
Finally, we want to notice that ``sage -t`` can also be executed on the ``.rst`` files of the documentation.
Do so to ensure correctness of examples in the documentation.
