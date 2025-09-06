#!/usr/bin/env python3
import sys
sys.path.append('.')
from modules.probes.xss_canary import classify_reflection, CANARY_KEY
from unittest.mock import patch, MagicMock

# Test the actual logic step by step
with patch('time.time', return_value=1234567890.123):
    full_canary = f"{CANARY_KEY}{int(1234567890.123*1000)}"
    mock_response = MagicMock()
    mock_response.content = f'<div>{full_canary}</div>'.encode()
    
    print(f"Full canary: {full_canary}")
    print(f"Base canary: {CANARY_KEY}")
    print(f"Response content: {mock_response.content}")
    
    # Test the actual logic from the function
    body = mock_response.content
    print(f"Body: {body}")
    print(f"CANARY_KEY.encode(): {CANARY_KEY.encode()}")
    print(f"CANARY_KEY.encode() in body: {CANARY_KEY.encode() in body}")
    
    if CANARY_KEY.encode() not in body:
        print("Returning 'none' because canary not in body")
    else:
        print("Canary found in body, checking contexts...")
        
        # Test regex patterns
        import re
        ATTR_PAT = re.compile(rb'''[a-zA-Z-]+\s*=\s*("|')(?P<val>[^"']*__ELISE__[^"']*)\1''')
        SCRIPT_BLOCK_PAT = re.compile(rb"<script\b[^>]*>(?P<body>.*?)</script>", re.I | re.S)
        
        print(f"ATTR_PAT search: {ATTR_PAT.search(body)}")
        print(f"SCRIPT_BLOCK_PAT search: {list(SCRIPT_BLOCK_PAT.finditer(body))}")
        
        # Check JS context
        for m in SCRIPT_BLOCK_PAT.finditer(body):
            if CANARY_KEY.encode() in m.group("body"):
                print("Found canary in script block")
                if b'"' + CANARY_KEY.encode() in m.group("body") or b"'" + CANARY_KEY.encode() in m.group("body"):
                    print("Found canary in quotes - should return 'js_string'")
                else:
                    print("Found canary in script but not in quotes - should return 'js_string'")
                break
        else:
            print("No canary found in script blocks")
        
        # Check attribute context
        if ATTR_PAT.search(body):
            print("Found canary in attribute - should return 'attr'")
        else:
            print("No canary found in attributes")
        
        print("Should return 'html' as default")
