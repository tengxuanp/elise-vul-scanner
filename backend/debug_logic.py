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
    print(f"Base canary in response: {CANARY_KEY.encode() in mock_response.content}")
    print(f"Full canary in response: {full_canary.encode() in mock_response.content}")
    
    # Test the regex patterns
    import re
    ATTR_PAT = re.compile(rb'''[a-zA-Z-]+\s*=\s*("|')(?P<val>[^"']*__ELISE__[^"']*)\1''')
    SCRIPT_BLOCK_PAT = re.compile(rb"<script\b[^>]*>(?P<body>.*?)</script>", re.I | re.S)
    
    print(f"ATTR_PAT search: {ATTR_PAT.search(mock_response.content)}")
    print(f"SCRIPT_BLOCK_PAT search: {list(SCRIPT_BLOCK_PAT.finditer(mock_response.content))}")
    
    # Test the actual function
    with patch('httpx.Client') as mock_client:
        mock_client.return_value.__enter__.return_value.request.return_value = mock_response
        
        result = classify_reflection(
            url='http://localhost:5001/search',
            method='GET',
            in_='query',
            param='q'
        )
        print(f'Function result: {result}')
