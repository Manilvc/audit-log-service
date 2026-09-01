"""Public wire contracts for the HTTP API.

Request and response Pydantic models with ``extra="forbid"``. Kept separate
from ``app.domain.events`` so emitters stay forgiving while the stored document
stays strict and fully normalised.
"""
