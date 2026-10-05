r"""
Logging setup of CiVerLy.

All modules of CiVerLy log to child loggers of the package logger
``civerly``. Messages of level ``INFO`` and above are printed to the console
(message only, without any prefix), unless they stem from a
:class:`CiverlyError`, since raised exceptions are already reported by their
traceback.

In addition, :meth:`civerly.cipher.Cipher.analyse` appends all messages of an
analysis run, including the exceptions, to a log file in
``model_options.path``, see :func:`analysis_log`.

The console output can be silenced via the standard ``logging`` interface::

    sage: import logging
    sage: logging.getLogger("civerly").setLevel(logging.WARNING)
    sage: logging.getLogger("civerly").setLevel(logging.INFO)
"""

import logging
import sys
from contextlib import contextmanager

PACKAGE_LOGGER_NAME = "civerly"
LOG_FILE_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


class _ConsoleHandler(logging.StreamHandler):
    r"""
    Handler writing to the *current* ``sys.stderr``, i.e. the stream is
    looked up at the time of emitting (like ``logging.lastResort``). This
    keeps the output visible when ``sys.stderr`` is replaced, e.g. by the
    doctest framework.
    """

    def __init__(self):
        super().__init__(sys.stderr)

    @property
    def stream(self):
        return sys.stderr

    @stream.setter
    def stream(self, _value):
        pass


def _is_not_exception(record):
    return not getattr(record, "civerly_exception", False)


def _setup_package_logger():
    package_logger = logging.getLogger(PACKAGE_LOGGER_NAME)
    if any(isinstance(h, _ConsoleHandler) for h in package_logger.handlers):
        return
    console = _ConsoleHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("%(message)s"))
    console.addFilter(_is_not_exception)
    package_logger.addHandler(console)
    package_logger.setLevel(logging.INFO)
    # Avoid duplicate console output if the root logger is configured.
    package_logger.propagate = False


_setup_package_logger()


@contextmanager
def analysis_log(log_file):
    r"""
    Context manager writing all messages of the ``civerly`` logger to
    ``log_file`` while active. The messages are appended, so an existing
    file is extended and contains the messages of all analysis runs. If
    ``log_file`` is ``None``, nothing is written.

    TESTS::

        sage: import logging, tempfile
        sage: from pathlib import Path
        sage: from civerly.log import analysis_log
        sage: with tempfile.TemporaryDirectory() as tmpdir:
        ....:   log_file = Path(tmpdir) / "run.log"
        ....:   with analysis_log(log_file):
        ....:       logging.getLogger("civerly.test").info("Hello")
        ....:   logging.getLogger("civerly.test").info("Not in file")
        ....:   print(log_file.read_text().strip().endswith("civerly.test: Hello"))
        Hello
        Not in file
        True

    A failed analysis run followed by a corrected one. The user forgets to
    choose a linear layer modeling, which is required for the wordwise model
    of AES::

        sage: # optional - glpk
        sage: import tempfile
        sage: from civerly.cipher_implementations.aes import AES_CVL
        sage: from civerly.model_options import *
        sage: aes = AES_CVL(R=2)
        sage: with tempfile.TemporaryDirectory(delete=False) as tmpdir:
        ....:   model_options = MODEL_OPTIONS(
        ....:       cryptanalysis=CRYPTANALYSIS.DIFFERENTIAL,
        ....:       optimization=OPTIMIZATION.MILP,
        ....:       granularity=GRANULARITY.WORDWISE,
        ....:       milp_solver=SOLVER.GLPK,
        ....:       path=Path(tmpdir))
        sage: aes.analyse(model_options)
        Traceback (most recent call last):
        ...
        civerly.model_options.InvalidModelOptionError: Invalid linear layer modeling option None!

    The exception is not printed by the console handler, but it is written to
    the log file. After correcting the model options, the analysis succeeds.
    As the log file is extended by each run, it contains the messages of both runs::

        sage: # optional - glpk
        sage: model_options.linear_layer_modeling = LINEAR_LAYER_MODELING.BRANCH_NUMBER
        sage: aes.analyse(model_options)
        644 variables and 653 constraints were written to '...AES.mps'
        5
        sage: aes.analyse(model_options)
        Using existing MILP model, make sure it is up to date!
        644 variables and 653 constraints were written to ...
        Using existing file ..., make sure it is up to date!
        5
        sage: log_file = Path(tmpdir) / f"{aes.name}_civerly.log"
        sage: with open(log_file, "r") as f:
        ....:    print(f.read()[:-1])
        ... [ERROR] civerly.model_options: InvalidModelOptionError: Invalid linear layer modeling option None!
        ... [INFO] civerly.sboxcipher: 644 variables and 653 constraints were written to ...
        ... [INFO] civerly.cipher: Using existing MILP model, make sure it is up to date!
        ... [INFO] civerly.sboxcipher: 644 variables and 653 constraints were written to ...
        ... [INFO] civerly.solvers: Using existing file ..., make sure it is up to date!

    Remove files::

        sage: import shutil
        sage: shutil.rmtree(tmpdir, ignore_errors=True)
    """
    if log_file is None:
        yield
        return
    package_logger = logging.getLogger(PACKAGE_LOGGER_NAME)
    handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    handler.setFormatter(logging.Formatter(LOG_FILE_FORMAT))
    package_logger.addHandler(handler)
    try:
        yield
    finally:
        package_logger.removeHandler(handler)
        handler.close()


class CiverlyError(Exception):
    r"""
    Base class of all custom exceptions of CiVerLy. Creating such an exception
    logs its message with level ``ERROR``, so that it shows up in the log file
    of the analysis run (see :func:`analysis_log`). It is not printed to the
    console, as the traceback already shows it.

    TESTS::

        sage: from civerly.log import CiverlyError
        sage: raise CiverlyError("Something went wrong")
        Traceback (most recent call last):
        ...
        civerly.log.CiverlyError: Something went wrong
    """

    def __init__(self, *args):
        super().__init__(*args)
        logging.getLogger(type(self).__module__).error(
            f"{type(self).__name__}: {self}", extra={"civerly_exception": True}
        )
