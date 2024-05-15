from jose import jws
import json, requests, hashlib

# Load private key
privateKey = open('private.key').read()

payload = {
    'id': 12345,
    'message': 'hello, i am thuan'
}

# Convert json to string
payload_str = json.dumps(payload)

# Hash payload, convert to byte
hashed_payload = hashlib.sha256(payload_str.encode("utf-8")).digest()

print("Before sign:", hashed_payload)

# Sign with private key
signed_payload = jws.sign(payload=hashed_payload, key=privateKey, algorithm='RS256')

#print("After sign:", signed_payload)

# Send payload to server
r = requests.post(url='http://localhost:8000/verify', data=payload_str, headers={'signature': signed_payload})

print(r.content)
