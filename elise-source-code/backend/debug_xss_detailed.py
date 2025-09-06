#!/usr/bin/env python3
import sys
sys.path.append('.')
from modules.probes.xss_canary import classify_reflection, CANARY_KEY
from unittest.mock import patch, MagicMock
import time

# Test with mocked response
mock_response = MagicMock()
mock_response.content = b'<div>__ELISE__1234567890</div>'

print(f"Testing XSS canary classification...")
print(f"CANARY_KEY: {CANARY_KEY}")

with patch('httpx.Client') as mock_client:
    mock_client.return_value.__enter__.return_value.request.return_value = mock_response
    
    with patch('time.time', return_value=1234567890.123):
        # Test the actual canary generation
        value = f"{CANARY_KEY}{int(1234567890.123*1000)}"
        print(f"Generated canary value: {value}")
        
        result = classify_reflection(
            url='http://localhost:5001/search',
            method='GET',
            in_='query',
            param='q'
        )
        print(f'Result: {result}')
        print(f'Response content: {mock_response.content}')
        canary_bytes = CANARY_KEY.encode()
        print(f'Canary bytes: {canary_bytes}')
        print(f'Canary in content: {canary_bytes in mock_response.content}')
        
        # Test the regex patterns
        import re
        ATTR_PAT = re.compile(rb'''[a-zA-Z-]+\s*=\s*("|')(?P<val>[^"']*__ELISE__[^"']*)\1''')
        SCRIPT_BLOCK_PAT = re.compile(rb"<script\b[^>]*>(?P<body>.*?)</script>", re.I | re.S)
        
        print(f"ATTR_PAT search: {ATTR_PAT.search(mock_response.content)}")
        print(f"SCRIPT_BLOCK_PAT search: {list(SCRIPT_BLOCK_PAT.finditer(mock_response.content))}")
