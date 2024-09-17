#!/usr/bin/env python

from random import choice
from argparse import ArgumentParser, FileType
from configparser import ConfigParser
from confluent_kafka import Producer

import json
import base64

from encryption import encrypt_data, KEY_ID, TOPIC

if __name__ == '__main__':
    # Parse the command line.
    parser = ArgumentParser()
    parser.add_argument('config_file', type=FileType('r'))
    args = parser.parse_args()

    # Parse the configuration.
    # See https://github.com/edenhill/librdkafka/blob/master/CONFIGURATION.md
    config_parser = ConfigParser()
    config_parser.read_file(args.config_file)
    config = dict(config_parser['default'])

    # Create Producer instance
    producer = Producer(config)
    topic = TOPIC

    # Optional per-message delivery callback (triggered by poll() or flush())
    # when a message has been successfully delivered or permanently
    # failed delivery (after retries).
    def delivery_callback(err, msg):
        if err:
            print('ERROR: Message failed delivery: {}'.format(err))
        else:
            print("Produced event to topic {topic}: key = {key:12} value = {value:12}".format(
                topic=msg.topic(), key=msg.key().decode('utf-8'), value=msg.value().decode('utf-8')))

    # Produce data by selecting random values from these lists.
    example_keys = ['eabara', 'jsmith', 'sgarcia', 'jbernard', 'htanaka', 'awalther']
    exmample_dicts = [{'book': 'book'}, {'alarm clock': 'alarm clock'}, {'t-shirts': 't-shirts'}, {'gift card': 'gift card'}, {'batteries': 'batteries'}]

    for _ in range(10):
        key = choice(example_keys)
        data_message = json.dumps(choice(exmample_dicts)).encode("utf-8")

        # Encrypting the data
        (
            ciphertext_blob,
            encoded_ciphertext_blob,
            encrypted_data_key,
            encoded_encrypted_data_key,
            iv,
        ) = encrypt_data(data_message, KEY_ID)

        # example with all components in payload
        # iv = base64.b64encode(iv)
        # payload = json.dumps({"encoded_ciphertext_blob": encoded_ciphertext_blob.decode('ascii'),
        #            "encoded_encrypted_data_key": encoded_encrypted_data_key.decode('ascii'),
        #            "iv": iv.decode('ascii')})

        # example with encrypted message in payload, DEK and IV in headers
        payload = encoded_ciphertext_blob
        headers = {"encoded_encrypted_data_key": encoded_encrypted_data_key,
                   "iv": iv}

        print(f"ORIGINAL (UNENCRYPTED): {data_message=}")
        print(f"ENCRYPTED PAYLOAD: {payload=}")
        print(f"HEADERS: {headers=}")

        producer.produce(topic, payload, key, callback=delivery_callback, headers=headers)

    # Block until the messages are sent.
    producer.poll(10000)
    producer.flush()