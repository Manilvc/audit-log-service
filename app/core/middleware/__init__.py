"""ASGI middleware applied in a fixed order.

Request-id / context, security headers, body-size limit, and per-principal
rate limiting. Order matters: later middleware sees whatever earlier layers
already rejected or annotated.
"""
