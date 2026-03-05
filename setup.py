from setuptools import setup
from Cython.Build import cythonize
import glob

sources = glob.glob("*.py") + glob.glob("proxy/*.py")

# Exclude setup.py itself and tests
sources = [f for f in sources if f not in ("setup.py", "tester.py") and not f.startswith("tests/")]

setup(
    ext_modules=cythonize(
        sources,
        compiler_directives={"language_level": "3"},
        nthreads=4,
    )
)
