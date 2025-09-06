#!/usr/bin/env python3
import sys
sys.path.append('.')
from modules.probes.xss_canary import classify_reflection, CANARY_KEY
from unittest.mock import patch, MagicMock

# Test with mocked response
mock_response = MagicMock()
mock_response.content = f'<div>{CANARY_KEY}</div>'.encode()

print(f"Testing with response: {mock_response.content}")
print(f"CANARY_KEY: {CANARY_KEY}")
print(f"CANARY_KEY.encode(): {CANARY_KEY.encode()}")

with patch('httpx.Client') as mock_client:
    mock_client.return_value.__enter__.return_value.request.return_value = mock_response
    
    with patch('time.time', return_value=1234567890.123):
        result = classify_reflection(
            url='http://localhost:5001/search',
            method='GET',
            in_='query',
            param='q'
        )
        print(f'Result: {result}')
