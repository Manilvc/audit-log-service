"""Durable ingest pipeline between the API and Elasticsearch / WORM.

``stream``
    Redis Streams producer/consumer groups, partitions, and dead-letter queues.
``chain``
    Atomic sequence reservation and hash-chain head commits (Lua).
``worker``
    Separate process: encrypt → chain → bulk index → seal archive → ack.
"""
