{
  description = "Dev shell with CiVerLy and its dependencies";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    nix-appimage = {
      url = "github:ralismark/nix-appimage";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      nix-appimage,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            (final: prev: {
              sage = prev.sage.override { requireSageTests = false; };
            })
          ];
        };


        espresso = pkgs.stdenv.mkDerivation {
          pname = "espresso";
          version = "2.4";

          src = pkgs.fetchFromGitHub {
            owner = "hadipourh";
            repo = "espresso";
            rev = "v3.0";
            sha256 = "sha256-1cR5fLgmZwVW7wmR/nJIDoW8fKP0XwSpbgPPSzoMKYo=";
          };

          nativeBuildInputs = [ pkgs.cmake ];

        };

        pyproject = builtins.fromTOML (builtins.readFile ./pyproject.toml);
        project = pyproject.project;
        civerly = pkgs.python3Packages.buildPythonPackage {
          ## Set the package name:
          pname = project.name;

          ## Inherit the package version:
          inherit (project) version;

          ## Set the package format:
          format = "pyproject";

          ## Set the package source:
          src = ./.;

          ## Specify the build system to use:
          build-system = with pkgs.python3Packages; [
            setuptools
          ];

        };

        # Sage with civerly as an extra Python package
        sageWithCiverly = pkgs.sage.override { extraPythonPackages = ps: [ civerly ]; };

        # The Python environment used by sage (first buildInput of sage.with-env)
        sagePythonEnv = builtins.head sageWithCiverly.with-env.buildInputs;

        # Create a patched version of sage-with-env that fixes the sage-venv-config shebang.
        # The sage-venv-config script has a placeholder shebang (#! /doesnotexist/python3)
        # that is intentionally non-functional (to prevent accidental execution before
        # proper installation). In the AppImage's squashfs mount, the shell's -x test
        # incorrectly reports this file as executable (due to squashfs mount semantics),
        # causing sage to try to run it and produce a "bad interpreter" error.
        # This patches the shebang to use the correct Python interpreter.
        patchedSageWithEnv = pkgs.runCommand "sage-with-env-patched-${sageWithCiverly.with-env.version}" {
          inherit (sageWithCiverly.with-env) meta;
          # Ensure sagePythonEnv is in the closure by making it a buildInput
          buildInputs = [ sagePythonEnv ];
        } ''
          cp -r ${sageWithCiverly.with-env} $out
          chmod -R u+w $out
          if [ -f $out/bin/sage-venv-config ]; then
            # Fix the shebang to use the correct Python interpreter
            sed -i "1s|^#! */doesnotexist/python3|#!${sagePythonEnv}/bin/python3|" $out/bin/sage-venv-config
            # Make the script executable so the shebang can actually run
            chmod +x $out/bin/sage-venv-config
          fi
        '';

        # Build pip-installable packages for use with sage's Python.
        # Uses pkgs.python3 which is the same Python that sage is built against.
        civerlyWheel = pkgs.stdenv.mkDerivation {
          pname = "${project.name}-wheel";
          inherit (project) version;
          src = ./.;
          nativeBuildInputs = with pkgs.python3Packages; [
            python
            build
            setuptools
            wheel
          ];
          buildPhase = ''
            python -m build --wheel --no-isolation
          '';
          installPhase = ''
            mkdir -p $out
            cp dist/*.whl $out/
          '';
        };

        civerlySdist = pkgs.stdenv.mkDerivation {
          pname = "${project.name}-sdist";
          inherit (project) version;
          src = ./.;
          nativeBuildInputs = with pkgs.python3Packages; [
            python
            build
            setuptools
            wheel
          ];
          buildPhase = ''
            python -m build --sdist --no-isolation
          '';
          installPhase = ''
            mkdir -p $out
            cp dist/*.tar.gz $out/
          '';
        };

        versionsRst = pkgs.writeText "versions.rst" ''
          ========
          Versions
          ========

          The following table lists the versions of the dependencies used in this build.

          .. list-table:: Dependency Versions
             :header-rows: 1
             :widths: 30 20

             * - Package
               - Version
             * - SageMath
               - ${pkgs.sage.version}
             * - SCIP
               - ${pkgs.scipopt-scip.version}
             * - CryptoMiniSat
               - ${pkgs.cryptominisat.version}
             * - CaDiCaL
               - ${pkgs.cadical.version}
             * - GLPK
               - ${pkgs.glpk.version}
             * - Espresso
               - ${espresso.version}
        '';

        civerlyDocsHtml = pkgs.stdenv.mkDerivation {
          pname = "civerly-docs-html";
          inherit (project) version;
          src = ./.;

          nativeBuildInputs = [
            sageWithCiverly
          ];

          buildPhase = ''
            export HOME=$(mktemp -d)
            unset SOURCE_DATE_EPOCH
            cp ${versionsRst} docs/source/installation/versions.rst
            sage -sh -c "sphinx-build -b html -d docs/build/doctrees docs/source docs/build/html"
          '';

          installPhase = ''
            cp -r docs/build/html $out
          '';
        };

        civerlyDocsPdf = pkgs.stdenv.mkDerivation {
          pname = "civerly-docs-pdf";
          inherit (project) version;
          src = ./.;

          nativeBuildInputs = [
            sageWithCiverly
            (pkgs.texliveSmall.withPackages (tp: [
              tp.latexmk
              tp.tex-gyre
              tp.fncychap
              tp.titlesec
              tp.tabulary
              tp.varwidth
              tp.framed
              tp.wrapfig
              tp.capt-of
              tp.needspace
              tp.upquote
              tp.parskip
              tp.cmap
            ]))
          ];

          buildPhase = ''
            export HOME=$(mktemp -d)
            unset SOURCE_DATE_EPOCH
            cp ${versionsRst} docs/source/installation/versions.rst
            sage -sh -c "sphinx-build -b latex -d docs/build/doctrees docs/source docs/build/latex"
            make -C docs/build/latex
          '';

          installPhase = ''
            mkdir -p $out
            cp docs/build/latex/civerly.pdf $out/
          '';
        };

        runtimeDeps = [
          sageWithCiverly
          pkgs.glpk
          pkgs.scipopt-scip
          pkgs.cryptominisat
          pkgs.cadical
          espresso
          pkgs.texliveSmall
        ];

        # The wrapper calls the patched sage-with-env directly, bypassing the
        # normal sage wrapper chain to use the fixed sage-venv-config.
        # It also sets PATH to include all runtime dependencies (solvers, etc.)
        # which ensures they're both available at runtime and included in the
        # AppImage closure.
        appimageWrapper = pkgs.writeShellScriptBin "civerly" ''
          export PATH="${pkgs.lib.makeBinPath runtimeDeps}:$PATH"
          exec ${patchedSageWithEnv}/bin/sage "$@"
        '';

      in
      {
        devShells.default = pkgs.mkShell {
          inputsFrom = [ civerly ];
          buildInputs = runtimeDeps ++ [
            pkgs.ruff
            pkgs.ty
            pkgs.codespell
            pkgs.lychee
          ];
        };

        packages = {
          "${project.name}" = civerly;
          default = civerly;
          wheel = civerlyWheel;
          sdist = civerlySdist;
          docs-html = civerlyDocsHtml;
          docs-pdf = civerlyDocsPdf;

          docker = pkgs.dockerTools.buildNixShellImage {
            name = project.name;
            tag = project.version;
            drv = self.outputs.devShells.${system}.default;
          };
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          appimage = nix-appimage.bundlers.${system}.default appimageWrapper;
        };

      }
    );
}
