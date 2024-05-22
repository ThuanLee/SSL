from fastapi import FastAPI, Request
from jose import jws
import json, hashlib, uvicorn

cert = open('certificate.crt').read()

app = FastAPI()

@app.post('/verify')
async def verify(request: Request):
    # Get signature, hash algorithm, sign algorithm
    signature = request.headers.get('signature')
    hash_alg = request.headers.get('hash_alg')
    sign_alg = request.headers.get('sign_alg')
 
    # Get payload
    payload = await request.body()
    payload_str = payload.decode("utf-8")
 
    # Hash payload with same algorithm with client
    if hash_alg == "SHA256": 
        hashed_payload = hashlib.sha256(payload_str.encode("utf-8")).digest()
    else:
        return {
            "reason": "Hash algorithm not supported",
            "verify": "failed"
        }

    # Verify signature with cert
    try:
        if sign_alg == "RS256": 
            verified_payload = jws.verify(token=signature, key=cert, algorithms='RS256')
        else:
            return {
                "reason": "Sign algorithm not supported",
                "verify": "failed"
            }
    except:
        return {
            "reason": "Payload is not signed with valid private key",
            "verify": "failed"
        }

    # Response
    if verified_payload == hashed_payload:
        return {
            "verify": "ok"
        }
    else:
        return {
            "reason": "Payload has been changed",
            "verify": "failed"
        }


if __name__ == "__main__":
    uvicorn.run("server:app",
                    host="0.0.0.0",
                    port=8000,
                    reload=True,
                    ssl_certfile='certificate.crt',
                    ssl_keyfile='private.key',
                    ssl_ca_certs='certificate.crt'
                )