===============
Automated Tests
===============

Naturally, we also implemented automated testing which is an indispensable foothold of modern software development.
On the one hand, these ensure that our models actually lead to the correct results.
On the other hand, they also make it easy to detect if further additions to the CiVerLy code break any functionality that was working correctly before.
Again, we mimic what ``sage`` does.
That is, the aforementioned docstrings can contain ``EXAMPLES`` and ``TESTS`` blocks.
These are made up of ``sage`` commands and their expected outputs.
This already is quite a useful addition to the documentation as examples often deepen the understanding of a function but ``sage`` can also automatically evaluate all those examples and verify that the computed output is indeed the output that was put in the docstring.

Tests involving external dependencies
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For obvious reasons, our tests must involve external tools like MILP and SAT solvers.
This however comes with some pitfalls.
For instance, consider a developer that wants to run all CiVerLy tests but who has not installed all solvers used by CiVerLy.
Luckily, ``sage`` provides a solution for this as tests can be marked as optional.
The implementations of ciphers in CiVerLy commonly feature tests like the following.

.. skip

.. code-block:: sage

   sage: import tempfile
   sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - glpk
   ....:   model_options = MODEL_OPTIONS(..., path=Path(tmpdir))
   ....:   aes.analyse(model_options)

The ``# optional - glpk`` marker on the ``with`` line causes the entire block to be skipped
when ``glpk`` is not in the optional flags.
Using ``tempfile.TemporaryDirectory`` as a context manager guarantees that the generated
model files are cleaned up automatically, even if the test fails.
The block is then only run when the ``sage -t`` invocation contains the optional ``glpk`` flag.
This in turn introduces a new pitfall.
A developer that forgets to put this optional flag will not notice that it is missing if the solver is installed.
This then makes the test fail for other developers that do not have the solver installed.
To prevent this scenario, we added some functionality to CiVerLy that can detect such missing optional flags.
In a nutshell, before invoking a solver CiVerLy checks if this solver was marked as disabled in an environment variable.
If this is the case, CiVerLy stops with an error.
More concretely,

.. code-block:: console

   env CIVERLY_DISABLE_GUROBI=1 sage -t --optional=sage,scip,glpk,cryptominisat,cadical,espresso src/civerly

will run all tests in CiVerLy except for those that require Gurobi.
If the tests invoke Gurobi anyway, CiVerLy will stop with an error.


Running tests
^^^^^^^^^^^^^

The quickest way to run the test suite is through the Makefile targets provided in the project root:

.. code-block:: console

   $ make test              # run all tests (no long-running tests, no solver flags)
   $ make test-ci           # run all tests with all CI solvers except Gurobi (includes --long and docs)
   $ make test-docs         # run tests on documentation only (with CI solvers)
   $ make test-extensive    # run all solver combinations with and without --long

The ``test-ci`` target is the same configuration used in CI for pull requests.
It runs both ``src/civerly`` and ``docs``.
To enable specific solvers or other options, pass variables on the command line:

.. code-block:: console

   $ make test SOLVERS='scip glpk'  # run tests with scip and glpk enabled
   $ make test LONG=1               # include long-running tests
   $ make test NTHREADS=4           # run tests with 4 parallel threads (default: 8)
   $ make test EXIT_FIRST=0         # continue after a failing test
   $ make test LOGFILE=my.log       # write output to a custom logfile

Tests are executed using ``sage -t``.
Extensive documentation for the ``sage`` doctesting framework is available `online <https://doc.sagemath.org/html/en/developer/doctesting.html>`_.
Here, we want to highlight some useful options.
First, we can mark doctests that will take long time as follows:

.. skip

.. code-block:: sage

   sage: import tempfile
   sage: with tempfile.TemporaryDirectory() as tmpdir:  # optional - gurobi  # long
   ....:   model_options = MODEL_OPTIONS(..., path=Path(tmpdir))
   ....:   present_cipher.analyse(model_options)

To include these when running the tests, add ``--long`` to the ``sage -t`` command.
Tests that exceed the threshold set by ``--warn-long`` (currently 180 seconds) will be reported as slow even without the ``# long`` marker.

Further, ``sage`` can run tests in parallel.
The Makefile passes ``--nthreads=8`` by default (``test-ci`` uses 2 to stay within CI resource limits);
override this with ``make test NTHREADS=4``.
When running in parallel, ensure that the different tests do not access the same files.

Another useful flag is ``--exitfirst`` which will stop all tests as soon as one failed.
Use ``--logfile=filename.log`` to write a log file.
Finally, we want to notice that ``sage -t`` can also be executed on the ``.rst`` files of the documentation.
Do so to ensure correctness of examples in the documentation.
