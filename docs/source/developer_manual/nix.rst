===
Nix
===

`Nix <https://nixos.org/>`_ is a package manager.
We kindly ask you to use it for developing CiVerLy.
This ensures that all developers of CiVerLy, as well as the CI pipeline, are using the same versions of ``sage`` and the other dependencies.

Setup
=====

First, `install Nix <https://nixos.org/download/>`_.
Then enable the `flakes <https://nixos.wiki/wiki/Flakes>`_ feature by adding the following line to ``~/.config/nix/nix.conf`` (create the file if it does not exist):

.. code-block:: text

   experimental-features = nix-command flakes

After that, clone the CiVerLy repository and run:

.. code-block:: console

   $ nix develop

This drops you into a shell with ``sage``, all supported solvers (SCIP, GLPK, CryptoMiniSat, CaDiCaL, Espresso), and all other development dependencies available.

Build targets
=============

The flake exposes several build targets, all invoked with ``nix build .#<target>``:

.. list-table::
   :header-rows: 1
   :widths: 20 80

   * - Target
     - Description
   * - ``default``
     - The CiVerLy Python package (same as ``civerly``).
   * - ``wheel``
     - A pip-installable ``.whl`` file, placed in ``result/``.
   * - ``sdist``
     - A source distribution ``.tar.gz``, placed in ``result/``.
   * - ``docs-html``
     - HTML documentation. Open ``result/index.html`` in a browser.
   * - ``docs-pdf``
     - PDF documentation, available as ``result/civerly.pdf``.
   * - ``docker``
     - A Docker image tarball. Load it with ``docker load < result``.
   * - ``appimage``
     - A self-contained AppImage (Linux only), placed in ``result``.

Updating dependencies
=====================

All dependency versions are pinned in ``flake.lock``.
To update them to the latest versions available from the configured channels, run:

.. code-block:: console

   $ nix flake update

Commit the resulting changes to ``flake.lock`` together with any code changes that require the updated dependencies.
