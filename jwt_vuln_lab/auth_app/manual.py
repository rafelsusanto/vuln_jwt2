

import json
import base64
import hmac
import hashlib

header = {"alg":"HS256","typ":"JWT"}

payload = {"user_id":1,"username":"username","exp":1710305789,"iat":1710132989}

# Step 1: Encode the header and payload
print(f"header = {header}")
print(f"json header = {json.dumps(header)}")
print(f"json header encode = {json.dumps(header).encode()}")
encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().replace("=", "")
print(f"encoded header1 : {base64.urlsafe_b64encode(json.dumps(header).encode())}")
print(f"encoded header2 : {base64.urlsafe_b64encode(json.dumps(header).encode()).decode()}")
print(f"encoded header3 : {encoded_header}")

encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().replace("=", "")

signature = hmac.new(
    key="weak".encode(),
    msg=f"{encoded_header}.{encoded_payload}".encode(),
    digestmod=hashlib.sha256
).digest()

encoded_signature = base64.urlsafe_b64encode(signature).decode().replace("=", "")

# Step 3: Form the JWT
jwt_token = f"{encoded_header}.{encoded_payload}.{encoded_signature}"

print(jwt_token)

# non_ascii_string = "こんにちは"  # "Hello" in Japanese
# encoded_bytes = non_ascii_string.encode('utf-8')
# print(encoded_bytes)  # Output will not be directly readable as "こんにちは"