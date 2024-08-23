"""Implementation of the Trusted Onboarding Key Infrastructure (TOKI) v0.2 zero-touch onboarding demo client."""

# Prerequisites:
# Client device must have an IDevID and corresponding private key
# Client device must have the certificate that signed the Ownership Certificate in its truststore (this CA should be unique per device)
# Server must have the Ownership Certificate and associated IDevID public key in DB
# Server must have the cert chain of the CA that signed the client's IDevID in its truststore

# Step 1: Discover the Trustpoint/TOKI Server service (mDNS)

# Step 2: Establish provisionally trusted TLS connection
# It is assumed that TLS client authentication is unavailable (IDevID not directly usable as client cert)

# Send onboarding request, including IDevID cert and a nonce for the server to sign to prove possession of the ownership key

# Step 3: Receive and verify the server's ownership certificate
# Note: For flexibility, the ownership certificate is independent of the server's TLS certificate
# However, client must ensure the server is in possession of the ownership key to prevent MitM attacks
# Therefore, the ownership key is used to sign the message (ownership_cert | nonce | server_tls_cert | {server_nonce})
# Server nonce is only required if TLS client authentication is unavailable

# Step 4: If client-side verification is successful, sign server_nonce with IDevID private key and send back to server
# # At this point, the client trusts the server and may e.g. accept the server's TLS certificate and EST truststore

# Step 5: Server verifies signed nonce and responds with an OTP to use as HTTP basicAuth credentials for EST simpleenroll

# Step 6: Client obtains the server's truststore (EST getcacerts)

# Step 7: Client sends a CSR to the server (EST simpleenroll with OTP obtained above)
# Step 8: Receive LDevID certificate

# ====================================================================
# Alternative, simpler protocol (TLS client authentication available):

# Step 1: Discover the Trustpoint/TOKI Server service (mDNS)

# Step 2: Establish provisionally trusted TLS connection, use IDevID as client cert

# Send onboarding request, including a nonce for the server to sign to prove possession of the ownership key

# Step 3: Receive and verify the server's ownership certificate
# Note: For flexibility, the ownership certificate is independent of the server's TLS certificate
# However, client must ensure the server is in possession of the ownership key to prevent MitM attacks
# Therefore, the ownership key is used to sign the message (ownership_cert | nonce | server_tls_cert)

# Step 4: If client-side verification is successful, client obtains the server's truststore (EST getcacerts)
# # At this point, the client trusts the server and may e.g. accept the server's TLS certificate and EST truststore

# Step 5: Client sends a CSR to the server (EST simpleenroll with IDevID as client cert)
# Step 6: Receive LDevID certificate
