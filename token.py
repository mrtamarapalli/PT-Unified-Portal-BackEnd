# Copyright 2017-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file
# except in compliance with the License. A copy of the License is located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an "AS IS"
# BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under the License.

import json
import time
import urllib.request
from jose import jwk, jwt
from jose.utils import base64url_decode

region = 'us-east-1'
userpool_id = 'us-east-1_0YRI34cxi'
app_client_id = '4rcj9d5gvssngt6t0bu2llg0dq'
keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, userpool_id)
# instead of re-downloading the public keys every time
# we download them only on cold start
# https://aws.amazon.com/blogs/compute/container-reuse-in-lambda/
with urllib.request.urlopen(keys_url) as f:
  response = f.read()
keys = json.loads(response.decode('utf-8'))['keys']

def lambda_handler(event, context):
    # token = event['token']
    token = "eyJraWQiOiJ4K3F0eGRQRUt5TnI1TFREV2s0RW1LeGc4cnFRYXVxVnpDTk9XXC9ETmhaaz0iLCJhbGciOiJSUzI1NiJ9.eyJhdF9oYXNoIjoiNHNuVjRyQjY1NjI1cGhxTzQtOUFYdyIsInN1YiI6ImY0NDgwNDQ4LWQwZjEtNzBhNC1iMTliLTgwNzBmMmVmZTcwZCIsInpvbmVpbmZvIjoiVU5LTk9XTiIsImNvZ25pdG86Z3JvdXBzIjpbIkwxR3JvdXBJbmZyYSIsInVzLWVhc3QtMV8wWVJJMzRjeGlfb2t0YWlkcCJdLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsImlzcyI6Imh0dHBzOlwvXC9jb2duaXRvLWlkcC51cy1lYXN0LTEuYW1hem9uYXdzLmNvbVwvdXMtZWFzdC0xXzBZUkkzNGN4aSIsImNvZ25pdG86dXNlcm5hbWUiOiJva3RhaWRwX2Rhd2VyZmlscGVAb2t0YWlkcC5jb20iLCJnaXZlbl9uYW1lIjoiZGF3ZXIiLCJub25jZSI6IlUxLXpOMXMycTlyeHJjcnBKQURmZFdkRXcyU0VFX2dhOFBuSUItRFV1VndjQzRudGVJZi13dlRTaFAyR3BLV1dBSGNacFNZRFYtaF9VUGt5RUdYQy11dkJuRGRPcm0xMzJaN0Z0WVNodDg5WnlEUldWZng2RkZuSm02d1NNVUltNE5qS1dMX3NJeVdIVG5xR2F3Z1JTYjJWQ1RmSXFkUFNTMVZrU2cyOHV5cyIsImF1ZCI6IjRyY2o5ZDVndnNzbmd0NnQwYnUybGxnMGRxIiwiaWRlbnRpdGllcyI6W3sidXNlcklkIjoiZGF3ZXJmaWxwZUBva3RhaWRwLmNvbSIsInByb3ZpZGVyTmFtZSI6Im9rdGFpZHAiLCJwcm92aWRlclR5cGUiOiJTQU1MIiwiaXNzdWVyIjoiaHR0cDpcL1wvd3d3Lm9rdGEuY29tXC9leGtiZW1mcjJ2amMxYnd6ajVkNyIsInByaW1hcnkiOiJ0cnVlIiwiZGF0ZUNyZWF0ZWQiOiIxNjk1MTc2Nzk5MDg4In1dLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTY5NzAyNjE1MSwibmFtZSI6IkRhd2VyIEZpbHBlIiwiZXhwIjoxNjk3MTEyNTUxLCJpYXQiOjE2OTcwMjYxNTEsImZhbWlseV9uYW1lIjoiZmlscGUiLCJqdGkiOiIyMTFjM2E2OC1lNGRmLTQwODItYWNhYi1jMDEzMTczYThhNWUiLCJlbWFpbCI6ImRhd2VyZmlscGVAb2t0YWlkcC5jb20ifQ.RxvOCN1Y5YFaqzL73EsGZBdFXypG3LNQVeO8L3sn_3nXkCUjqd8ERrzXZKCP0H8vMvtb0_XXCtnkUnUrr-zMlQYbQD6wKGafz7spRwubQQXiAwXLoGQ15MXB-Uek-MqW1Fv4q6pp1RA4N5SCMYSZ3G8OEWD6dmPdbP6QbuWfay-VYvKhAZXo8kxWRLoQRyWU3F0v48jruwBwX6gcsMoLVxSkgFfi3QC63oJcCE81Rbkqna2iIv4CTUh8nih5YIaOtj43UvzC7aLqZlDLTxLEncZuq4eGqf0HaiAtgrEIRxHF3-JkdXLOxAhLCtzp1z2j0dSJaasM2_xaF3ig3fMShg"
    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        print('Public key not found in jwks.json')
        return False
    # construct the public key
    public_key = jwk.construct(keys[key_index])
    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        print('Signature verification failed')
        return False
    print('Signature successfully verified')
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    # additionally we can verify the token expiration
    if time.time() > claims['exp']:
        print('Token is expired')
        return False
    # and the Audience  (use claims['client_id'] if verifying an access token)
    if claims['aud'] != app_client_id:
        print('Token was not issued for this audience')
        return False
    # now we can use the claims
    print(claims)

    policy = {
      "principalId": "user",
      "policyDocument": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Action": "execute-api:Invoke",
            "Effect": "allow",
            "Resource": "arn:aws:lambda:us-east-1:566692369023:function:sample_single_instance_details"
          }
        ]
      }
    }
    return policy
        
# the following is useful to make this script executable in both
# AWS Lambda and any other local environments
if __name__ == '__main__':
    # for testing locally you can enter the JWT ID Token here
    event = {'token': ''}
    lambda_handler(event, None)