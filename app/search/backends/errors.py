"""Engine-neutral errors the search port raises.

Every adapter translates its client library's exceptions into these, so nothing
above `app.search.backends` imports from `elasticsearch` or `opensearchpy`. That
is not tidiness for its own sake: `repository.py` and `keyring.py` branch on
"not found" and "conflict" to make real decisions - a missing data stream is
expected, a create conflict means another worker won a race - and those branches
have to keep working whichever engine is behind them.

The split is between *the caller got it wrong* (`SearchNotFound`,
`SearchConflict`, `SearchRejected`) and *the store cannot answer right now*
(`SearchUnavailable`), because those map to different HTTP statuses and, for the
worker, to different retry decisions.
"""

from __future__ import annotations


class SearchError(Exception):
    """Base class for every error the search port reports."""


class SearchNotFound(SearchError):
    """The document, index or data stream does not exist."""


class SearchConflict(SearchError):
    """A create lost a race, or a version check failed."""


class SearchRejected(SearchError):
    """The store refused the request: bad mapping, illegal argument, 4xx.

    The message is never returned to an API caller - an engine error body
    carries index names, mappings and sometimes another user's document
    content. `app.core.exceptions` logs it and answers with a generic 502.
    """


class SearchUnavailable(SearchError):
    """The store could not be reached, or timed out.

    Distinct from `SearchRejected` because it is worth retrying: the ingest
    queue holds the events, so a worker that sees this can back off and retry
    the same batch without losing evidence.
    """
