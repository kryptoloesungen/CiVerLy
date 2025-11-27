=================
Files of CiVerLy
=================

Here, we briefly discuss the different files that together make up CiVerLy.

Overview
========

.. code-block:: text

    civerly/
    │
    ├── src/
    │   └── civerly/
    │       ├── __init__.py
    │       ├── component.py
    │       ├── cipher.py
    │       ├── sboxcipher.py
    │       ├── wordsboxcipher.py
    │       ├── aeslike.py
    │       ├── wordbasedcipher.py
    │       ├── addrx.py
    │       ├── andrx.py
    │       ├── model_options.py
    │       ├── solvers.py
    │       ├── util.py
    │       ├── benchmark.py
    │       └── cipher_implementations/
    │           ├── aes.py
    │           └── ... (other files)
    ├── docs/
    │   ├── Makefile
    │   └── source/
    │       └── ... (other files)
    │
    ├── pyproject.toml
    ├── setup.py
    └── MANIFEST.in


Source Files
============
Most importantly, there are the source files in ``src/civerly``.
Many of those simply implement the class hierarchy for CiVerLy ciphers.
``component.py`` implements all components that are available in CiVerLy and
also contains the code to model each of these.
``model_options.py`` collects all the available options for modeling.
``solvers.py`` contains code to interact with external MILP and SAT solvers.
``util.py`` contains other utility functions and ``benchmark.py`` contains code
to generate benchmarks, i.e., timings for the generation and solving of models.
``cipher_implementations`` contains the implementation of some well-known
ciphers and also examples how these can be modeled with CiVerLy.


Doc Files
=========
``source`` contains the source files for this document and ``Makefile`` provides
the commands to build it.


Project Files
=============
``pyproject.toml``, ``setup.py`` and ``MANIFEST.in`` contain some information on
the CiVerLy (Python) project, e.g., its dependencies.
