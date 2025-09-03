
import sys
import os

# --- Setup Python Path ---
# This ensures that 'from backend...' imports work correctly.
# It mimics the behavior of the main application entrypoint.
print("--- Setting up Python path ---")
try:
    # Get the absolute path of the directory containing this file (backend/)
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"Backend directory: {backend_dir}")
    
    # Get the project root (the parent of the 'backend' directory)
    project_root = os.path.dirname(backend_dir)
    print(f"Project root: {project_root}")
    
    # Add the project root to sys.path
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
        print(f"✅ Added project root to Python path.")
    else:
        print(f"✅ Project root already in Python path.")
    
    print(f"Current sys.path: {sys.path[:3]}...")
    print("--- Path setup complete ---")

except Exception as e:
    print(f"🚨 ERROR in path setup: {e}")
    sys.exit(1)

# --- Test Import ---
# Now, attempt the import that was failing.
print("\n--- Attempting to import EnhancedFeatureExtractor ---")
try:
    from backend.modules.ml.enhanced_features import EnhancedFeatureExtractor
    print("✅ SUCCESS: 'from backend.modules.ml.enhanced_features import EnhancedFeatureExtractor' worked.")
    
    # Instantiate the class to be sure
    extractor = EnhancedFeatureExtractor()
    print("✅ SUCCESS: Instantiated EnhancedFeatureExtractor.")
    
    # Check if it's the real one or the dummy
    if "dummy" in getattr(extractor, "extract_enhanced_features", lambda: {"dummy": 0}).__doc__.lower():
         print("🚨 FAILED: Imported the DUMMY EnhancedFeatureExtractor class.")
    else:
         print("✅ SUCCESS: Imported the REAL EnhancedFeatureExtractor class.")

except ImportError as e:
    print(f"🚨 FAILED to import EnhancedFeatureExtractor.")
    print(f"ImportError: {e}")
except Exception as e:
    print(f"🚨 An unexpected error occurred: {e}")

# --- Test Inference Engine Import ---
print("\n--- Attempting to import EnhancedInferenceEngine ---")
try:
    from backend.modules.ml.enhanced_inference import EnhancedInferenceEngine
    print("✅ SUCCESS: 'from backend.modules.ml.enhanced_inference import EnhancedInferenceEngine' worked.")
    
    # Instantiate the engine
    engine = EnhancedInferenceEngine()
    print("✅ SUCCESS: Instantiated EnhancedInferenceEngine.")
    
    # Check if it fell back to the dummy class
    if "dummy" in engine.feature_extractor.__class__.__name__.lower():
        print("🚨 FAILED: Inference engine is using the DUMMY feature extractor.")
    else:
        print("✅ SUCCESS: Inference engine is using the REAL feature extractor.")

except ImportError as e:
    print(f"🚨 FAILED to import EnhancedInferenceEngine.")
    print(f"ImportError: {e}")
except Exception as e:
    print(f"🚨 An unexpected error occurred during inference engine test: {e}")

