# A Demonstration of envelope encryption on Kafka messaging.

This is a proof of concept demonstrating envelope encryption using AWS KMS for key management and simple Kafka message producing/consuming.

The code demonstrates two approaches for passing the Data Encryption Key (DEK) and the Initialization Vector (IV):

1. Pass by headers

- The encrypted message is passed as Base64 encoded directly as the payload.
- The DEK & IV are passed as Base64 encoded values via a headers Python dict.

2. Pass by message body.

- Achieved by constructing a Python dict where all encrypted byte type values are Base64 encoded and then transformed into a JSON dumped string.

To reproduce this demo:

1. export AWS credentials to the working terminal:

- `export AWS_ACCESS_KEY_ID="< your key id >"`
- `export AWS_SECRET_ACCESS_KEY="< your access key >"`

* For my fellow Hinge Health Engineers, you can obtain valid DEV keys from [HingePowerUser](https://hingehealthsso.awsapps.com/start/#/?tab=accounts) role.

2. Add an AWS CMK Key ARN to `encryption.py` `KEY_ID`

- Hinge Health Engineers, this can be generated via [Hinge_Engineer_Dev](https://hingehealthsso.awsapps.com/start/#/?tab=accounts) role under the `Key Management Service` interface.
- Note: this code is set for `us-east-1` zone.

3. Follow the steps in the resource `Kafka Producer/Consumer Python Tutorial`

4. Alter the payload examples to demonstrate your use case. Alter the DEK/IV passing mechanism to ensure your understanding.

Resources:

- [Kafka Producer/Consumer Python Tutorial](https://developer.confluent.io/get-started/python/?session_ref=https://search.brave.com/#introduction)
- [Confluent Apache Kafka Python Client](https://docs.confluent.io/kafka-clients/python/current/overview.html)
- [Envelope Encryption with AWS KMS - Python Example](https://gist.github.com/bharathkarumudi/6a6b8836c827d846167381d3ba42974d)
