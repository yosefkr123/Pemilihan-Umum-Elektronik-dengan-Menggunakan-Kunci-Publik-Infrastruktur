import http.client
import json

def test_server(port):
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {'Content-type': 'application/json'}
        body = json.dumps({"endpoint": "/test"})
        
        conn.request("POST", "/", body, headers)
        response = conn.getresponse()
        
        print(f"\nServer {port} Response:")
        print(f"Status: {response.status} {response.reason}")
        print("Headers:", response.getheaders())
        print("Body:", response.read().decode())
        
    except Exception as e:
        print(f"\nError on port {port}: {str(e)}")
    finally:
        conn.close()

# Test semua server
for port in [8081, 8082, 8083]:
    test_server(port)