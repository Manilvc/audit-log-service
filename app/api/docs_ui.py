"""Branded documentation UI.

FastAPI's stock ReDoc page loads its bundle from jsDelivr and its fonts from
Google Fonts. Three reasons that is the wrong shape for this service:

* **It forces the CSP open.** Serving the reference for an audit system from a
  page that executes third-party script is a poor trade for cosmetics.
* **It fails closed on a locked-down network.** An operator reading the API
  reference from inside a restricted environment - which is where an audit
  service tends to live - gets a blank page.
* **It is unbranded.** The page is the developer-facing surface of the platform.

So the bundle is vendored under ``app/static`` and the page is rendered here with
the EveryCRED palette. The font stack is the system stack rather than a webfont,
which keeps the page free of *any* external origin: the CSP for this route needs
nothing beyond ``'self'``.
"""

from __future__ import annotations

from typing import Final

# EveryCRED palette, taken from the platform frontend rather than invented, so
# the reference looks like the product it documents.
BRAND_DEEP: Final[str] = "#1a3668"  # header, right panel
BRAND_PRIMARY: Final[str] = "#1e4383"  # headings, primary accents
BRAND_LINK: Final[str] = "#0054e9"  # interactive text
BRAND_GOLD: Final[str] = "#ba9d37"  # sparingly: the environment badge
BRAND_CODE_BG: Final[str] = "#14294d"  # code blocks inside the dark panel

_SYSTEM_SANS: Final[str] = (
    "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
)
_SYSTEM_MONO: Final[str] = (
    "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace"
)


def redoc_html(
    *,
    openapi_url: str,
    title: str,
    script_url: str,
    environment: str,
    swagger_url: str | None,
) -> str:
    """Render the branded ReDoc page.

    Args:
        openapi_url: where the page fetches the schema from.
        title: document title, shown in the tab and the header.
        script_url: the vendored ReDoc bundle, served from this origin.
        environment: deployment tier, surfaced as a badge so a reader is never
            in doubt about which cluster they are pointed at.
        swagger_url: link to the interactive Swagger page, omitted when docs are
            served without it.

    Returns:
        A complete HTML document.
    """
    swagger_link = (
        f'<a class="nav-link" href="{swagger_url}">Interactive console</a>' if swagger_url else ""
    )

    # The environment badge is gold only when it is *not* production: on a prod
    # cluster it turns red, because "am I about to run this against production?"
    # is the question a docs page should answer without being asked.
    badge_color = "#c0392b" if environment == "prod" else BRAND_GOLD

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} - API Reference</title>
<style>
  :root {{
    --brand-deep: {BRAND_DEEP};
    --brand-primary: {BRAND_PRIMARY};
    --brand-link: {BRAND_LINK};
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; font-family: {_SYSTEM_SANS}; background: #ffffff; }}

  /* Brand bar ---------------------------------------------------------- */
  .topbar {{
    display: flex; align-items: center; gap: 16px;
    padding: 0 22px; height: 58px;
    background: var(--brand-deep);
    color: #ffffff;
    border-bottom: 3px solid var(--brand-primary);
  }}
  .mark {{
    display: inline-flex; align-items: center; justify-content: center;
    width: 30px; height: 30px; border-radius: 7px;
    background: linear-gradient(135deg, var(--brand-link), var(--brand-primary));
    font-weight: 700; font-size: 14px; letter-spacing: -0.4px; flex: none;
  }}
  .titles {{ display: flex; flex-direction: column; line-height: 1.25; min-width: 0; }}
  .titles strong {{ font-size: 14.5px; font-weight: 600; }}
  .titles span {{ font-size: 11.5px; opacity: 0.7; }}
  .badge {{
    font-size: 10.5px; font-weight: 700; letter-spacing: 0.7px; text-transform: uppercase;
    padding: 3px 9px; border-radius: 999px; color: #0d1b33;
    background: {badge_color}; flex: none;
  }}
  .spacer {{ flex: 1 1 auto; }}
  .nav-link {{
    color: #ffffff; opacity: 0.85; text-decoration: none;
    font-size: 13px; padding: 7px 11px; border-radius: 6px;
    border: 1px solid rgba(255,255,255,0.22); white-space: nowrap;
  }}
  .nav-link:hover {{ opacity: 1; background: rgba(255,255,255,0.10); }}

  /* Hide the topbar links on a narrow screen rather than let them wrap into
     the title and push it out of the bar. */
  @media (max-width: 640px) {{
    .nav-link {{ display: none; }}
    .titles span {{ display: none; }}
  }}

  /* ReDoc renders its own theme; only the surrounding chrome is styled here. */
  #redoc {{ display: block; }}
</style>
</head>
<body>
  <header class="topbar">
    <span class="mark">EC</span>
    <span class="titles">
      <strong>EveryCRED Audit Log</strong>
      <span>Tamper-evident activity record</span>
    </span>
    <span class="badge">{environment}</span>
    <span class="spacer"></span>
    {swagger_link}
    <a class="nav-link" href="{openapi_url}">OpenAPI spec</a>
  </header>

  <div id="redoc"></div>

  <script src="{script_url}"></script>
  <script>
    Redoc.init(
      "{openapi_url}",
      {{
        // Auth and the tenant header are the two things a reader needs before
        // anything else works, so the security block is never collapsed away.
        expandSingleSchemaField: true,
        expandResponses: "200,202",
        requiredPropsFirst: true,
        // Level 2, not 3: ReDoc builds every JSON sample eagerly at first
        // paint, and the search request model is wide enough that a deeper
        // expansion visibly stalls the initial render.
        jsonSampleExpandLevel: 2,
        hideDownloadButton: false,
        pathInMiddlePanel: true,
        // Sorting would scatter the event model across the page; declaration
        // order groups related fields the way the schema author intended.
        sortPropsAlphabetically: false,
        theme: {{
          colors: {{
            primary: {{ main: "{BRAND_PRIMARY}" }},
            success: {{ main: "#1e7f4b" }},
            warning: {{ main: "{BRAND_GOLD}" }},
            error:   {{ main: "#c0392b" }},
            text:    {{ primary: "#1e1e1e", secondary: "#4d4d4d" }},
            http: {{
              get: "#1e7f4b", post: "{BRAND_LINK}",
              put: "{BRAND_GOLD}", delete: "#c0392b"
            }}
          }},
          typography: {{
            fontSize: "15px",
            lineHeight: "1.6",
            fontFamily: "{_SYSTEM_SANS}",
            headings: {{ fontFamily: "{_SYSTEM_SANS}", fontWeight: "600" }},
            code: {{
              fontFamily: "{_SYSTEM_MONO}",
              fontSize: "13px",
              color: "#ffffff",
              backgroundColor: "{BRAND_CODE_BG}"
            }},
            links: {{ color: "{BRAND_LINK}", visited: "{BRAND_LINK}" }}
          }},
          sidebar: {{
            width: "292px",
            backgroundColor: "#f5f7fb",
            textColor: "{BRAND_DEEP}",
            activeTextColor: "{BRAND_LINK}"
          }},
          rightPanel: {{
            backgroundColor: "{BRAND_DEEP}",
            textColor: "#ffffff"
          }}
        }}
      }},
      document.getElementById("redoc")
    );
  </script>
</body>
</html>
"""
