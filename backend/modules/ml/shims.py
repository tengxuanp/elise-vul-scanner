from __future__ import annotations

"""
Joblib/Pickle compatibility shims for loading legacy models.

Provides minimal stand-ins for custom classes that were saved from notebooks or
scripts (e.g., ConstantProba defined in __main__). Also installs a numpy alias
for environments where models expect numpy._core (NumPy >=2) but runtime uses
NumPy 1.x.
"""

import sys
from types import SimpleNamespace


class ConstantProba:
    """Simple estimator that returns a constant probability for the positive class.

    Accepts scikit-learn-like calls: predict_proba(X) -> (n,2), predict(X) -> (n,).
    """

    def __init__(self, p: float = 0.5):
        self.p = float(p)

    def predict_proba(self, X):
        try:
            n = getattr(X, 'shape', [len(X)])[0]
        except Exception:
            n = 1
        import numpy as np
        p = float(self.p)
        pos = np.full((n, 1), p, dtype=float)
        neg = 1.0 - pos
        return np.concatenate([neg, pos], axis=1)

    def predict(self, X):
        import numpy as np
        proba = self.predict_proba(X)[:, 1]
        return (proba >= 0.5).astype(int)


def install_numpy_core_alias():
    """Map numpy._core -> numpy.core for compatibility with older NumPy.
    """
    try:
        import numpy as _np
        import importlib
        try:
            import numpy._core  # type: ignore
            return
        except Exception:
            pass
        sys.modules.setdefault('numpy._core', _np.core)
    except Exception:
        pass


def install_joblib_shims():
    """Install shims in likely module namespaces used during pickling.

    Many training notebooks pickle classes from __main__. Ensure our shim is
    reachable under that module as well as a generic placeholder.
    """
    try:
        main_mod = sys.modules.get('__main__')
        if main_mod is None:
            # Create a dummy __main__-like namespace
            main_mod = SimpleNamespace()
            sys.modules['__main__'] = main_mod  # type: ignore
        if not hasattr(main_mod, 'ConstantProba'):
            setattr(main_mod, 'ConstantProba', ConstantProba)
    except Exception:
        pass

