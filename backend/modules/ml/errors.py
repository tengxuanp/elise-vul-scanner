"""
ML Infrastructure Error Classes

Custom error types for ML model operations and predictions.
"""


class ModelNotReadyError(RuntimeError):
    """
    Raised when attempting to use an ML model that is not ready for predictions.
    
    This error should be used to block fake predictions and ensure that
    only properly initialized and trained models are used for inference.
    """
    pass
