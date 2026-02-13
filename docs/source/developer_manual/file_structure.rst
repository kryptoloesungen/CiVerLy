=================
Files of CiVerLy
=================

Here, we briefly discuss the different files that together make up CiVerLy.

Overview
========

.. code-block:: text

    civerly/
    │
    ├── docs
    │   └── source
    │       ├── ... (other files)
    ├── flake.lock
    ├── flake.nix
    ├── LICENSE
    ├── pyproject.toml
    ├── README.md
    └── src
        └── civerly
            ├── addrx.py
            ├── aeslike.py
            ├── andrx.py
            ├── benchmark.py
            ├── cipher_implementations
            │   ├── aes.py
            │   ├── ... (other files)
            ├── cipher.py
            ├── component.py
            ├── __init__.py
            ├── largesboxes
            │   ├── __init__.py
            │   ├── largesboxes.py
            │   └── lib-largesboxes.cpp
            ├── model_options.py
            ├── sboxcipher.py
            ├── solvers.py
            ├── trail.py
            ├── util.py
            ├── wordbasedcipher.py
            └── wordsboxcipher.py


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
``source`` contains all the source files for this document.


Project File
============
``pyproject.toml`` contains some information on the CiVerLy (Python) project.


LICENSE
=======
``LICENSE`` conatins the licence which is EUROPEAN UNION PUBLIC LICENCE v. 1.2 (EUPL 1.2) with an additional non-endorsement clause.


Nix
===
`Nix <https://nixos.org/>`_ is a package manager.
We use it to track all the dependencies of the CiVerLy project.
This is done in the ``flake.nix``.
The ``flake.lock`` contains hashes to pin all current versions.
