from fastapi import FastAPI, Request
from jose import jws
import json, hashlib, uvicorn

cert = open('certificate.crt').read()

app = FastAPI()

@app.post('/verify')
async def verify(request: Request):
    # Get signature
    signed_payload = request.headers.get('signature')
    # Get payload
    payload = await request.body()
    payload_str = payload.decode("utf-8")
 
    # Hash payload with same algorithm with client
    hashed_payload = hashlib.sha256(payload_str.encode("utf-8")).digest()
    print(payload_str)

    # Verify with public key
    try:
        verified_payload = jws.verify(token=signed_payload, key=cert, algorithms='RS256')
    except:
        return {
            "reason": "payload is not signed with CA cert",
            "verify": "failed"
        }

    # Response
    if verified_payload == hashed_payload:
        return {
            "signature": signed_payload,
            "payload": payload_str,
            "verify": "ok"
        }
    else:
        return {
            "reason": "payload has been changed",
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