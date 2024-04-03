#!/usr/bin/env python

import sys
from argparse import ArgumentParser, FileType
from configparser import ConfigParser
from confluent_kafka import Consumer, OFFSET_BEGINNING

import json
import base64
from encryption import decrypt_data, KEY_ID, TOPIC

if __name__ == '__main__':
    # Parse the command line.
    parser = ArgumentParser()
    parser.add_argument('config_file', type=FileType('r'))
    parser.add_argument('--reset', action='store_true')
    args = parser.parse_args()

    # Parse the configuration.
    # See https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md
    config_parser = ConfigParser()
    config_parser.read_file(args.config_file)
    config = dict(config_parser['default'])
    config.update(config_parser['consumer'])

    # Create Consumer instance
    consumer = Consumer(config)
    topic = TOPIC

    # Set up a callback to handle the '--reset' flag.
    def reset_offset(consumer, partitions):
        if args.reset:
            for p in partitions:
                p.offset = OFFSET_BEGINNING
            consumer.assign(partitions)

    # Subscribe to topic
    consumer.subscribe([topic], on_assign=reset_offset)

    # Poll for new messages from Kafka and print them.
    try:
        while True:
            msg = consumer.poll(1.0)
            if msg is None:
                # Initial message consumption may take up to
                # `session.timeout.ms` for the consumer group to
                # rebalance and start consuming
                print("Waiting...")
            elif msg.error():
                print("ERROR: %s".format(msg.error()))
            else:
                payload = msg.value()
                headers = dict(msg.headers()) # [(b'encoded_encrypted_data_key', b''), (b'iv', b'']

                print(f"HEADERS: {headers=}")
                print(f"ENCRYPTED: {payload=}")

                # example with encrypted message in payload, DEK and IV in headers
                descrypted_data = decrypt_data(encoded_ciphertext_blob=payload,
                                               encoded_encrypted_data_key=headers['encoded_encrypted_data_key'],
                                               iv=headers['iv'])

                # example with all components in payload
                # descrypted_data = decrypt_data(encoded_ciphertext_blob=payload['encoded_ciphertext_blob'].encode('ascii'),
                #                                encoded_encrypted_data_key=payload['encoded_encrypted_data_key'].encode('ascii'),
                #                                iv=base64.b64decode(payload['iv'].encode('ascii')))

                print(f"DECRYPTED PAYLOAD: {json.loads(str(descrypted_data, 'utf-8'))}")
    except KeyboardInterrupt:
        pass
    finally:
        # Leave group and commit final offsets
        consumer.close()