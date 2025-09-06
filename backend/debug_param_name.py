#!/usr/bin/env python3
import sys
sys.path.append('.')
from modules.probes.xss_canary import classify_reflection, CANARY_KEY
from unittest.mock import patch, MagicMock

# Test the parameter name issue
with patch('time.time', return_value=1234567890.123):
    full_canary = f"{CANARY_KEY}{int(1234567890.123*1000)}"
    mock_response = MagicMock()
    mock_response.content = f'<div>{full_canary}</div>'.encode()
    
    print(f"Testing parameter name issue...")
    
    # Test with different parameter names
    for param_name in ['query', 'form', 'json', 'invalid']:
        print(f"\nTesting with in_='{param_name}':")
        
        with patch('httpx.Client') as mock_client:
            client_instance = MagicMock()
            mock_client.return_value.__enter__.return_value = client_instance
            client_instance.request.return_value = mock_response
            
            result = classify_reflection(
                url='http://localhost:5001/search',
                method='GET',
                in_=param_name,
                param='q'
            )
            
            print(f"Result: {result}")
            print(f"Request called: {client_instance.request.called}")
            
            if client_instance.request.called:
                call_args = client_instance.request.call_args
                print(f"Request method: {call_args[0][0] if call_args[0] else 'None'}")
                print(f"Request URL: {call_args[0][1] if len(call_args[0]) > 1 else 'None'}")
