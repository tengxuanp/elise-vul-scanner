#!/usr/bin/env python3
import sys
sys.path.append('.')
from modules.probes.xss_canary import classify_reflection, CANARY_KEY
from unittest.mock import patch, MagicMock

# Test with mocked response containing the full canary
with patch('time.time', return_value=1234567890.123):
    full_canary = f"{CANARY_KEY}{int(1234567890.123*1000)}"
    mock_response = MagicMock()
    mock_response.content = f'<div>{full_canary}</div>'.encode()
    
    print(f"Testing with full canary: {full_canary}")
    print(f"Response content: {mock_response.content}")
    
    with patch('httpx.Client') as mock_client:
        mock_client.return_value.__enter__.return_value.request.return_value = mock_response
        
        result = classify_reflection(
            url='http://localhost:5001/search',
            method='GET',
            in_='query',
            param='q'
        )
        print(f'Result: {result}')
