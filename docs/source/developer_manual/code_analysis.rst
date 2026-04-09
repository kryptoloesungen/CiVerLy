=============
Code Analysis
=============

CiVerLy uses several tools to enforce code quality and consistency.
All of them are available through Makefile targets in the project root.
Run all checks at once with:

.. code-block:: console

   $ make lint

This runs the linter, checks formatting, scans for spelling mistakes, and verifies that all hyperlinks are alive.
The individual tools and their targets are described below.

Linting
^^^^^^^

`Ruff <https://docs.astral.sh/ruff/>`_ is used as the linter and formatter.

.. code-block:: console

   $ make check          # report linting violations
   $ make check-fix      # report and auto-fix linting violations
   $ make format         # reformat source files in-place
   $ make format-check   # check formatting without modifying files

Spell checking
^^^^^^^^^^^^^^

`codespell <https://github.com/codespell-project/codespell>`_ checks for common spelling mistakes in source files and documentation:

.. code-block:: console

   $ make spell

Link checking
^^^^^^^^^^^^^

`lychee <https://lychee.cli.rs/>`_ verifies that all hyperlinks in the repository are alive:

.. code-block:: console

   $ make check-links
