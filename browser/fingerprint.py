"""
Coherent real-laptop fingerprint profiles.

The reason headless browsers get silently refused by EtherHiding stage-1 gates is
*inconsistency* — a UA claiming Windows while navigator.platform says Linux, or a
WebGL renderer of "SwiftShader" (the dead giveaway of a software-rendered headless
browser). Each profile here is internally consistent across UA, UA-CH, platform,
WebGL vendor/renderer, hardware, screen and timezone, so the gate sees an ordinary
consumer laptop and lets the eth_call chain fire.

The escalation ladder (server.py) rotates through these profiles across attempts.
"""

from __future__ import annotations

# Each profile is a fully consistent desktop/laptop identity.
PROFILES: list[dict] = [
    {
        "id": "win11-chrome-nvidia",
        "ua": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"),
        "platform": "Win32",
        "ua_platform": "Windows",
        "ua_platform_version": "15.0.0",
        "brands": [
            {"brand": "Not(A:Brand", "version": "99"},
            {"brand": "Google Chrome", "version": "133"},
            {"brand": "Chromium", "version": "133"},
        ],
        "hardware_concurrency": 8,
        "device_memory": 8,
        "webgl_vendor": "Google Inc. (NVIDIA)",
        "webgl_renderer": ("ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 "
                           "vs_5_0 ps_5_0, D3D11)"),
        "languages": ["en-US", "en"],
        "locale": "en-US",
        "timezone": "America/New_York",
        "screen": {"width": 1920, "height": 1080, "depth": 24},
        "viewport": {"width": 1920, "height": 937},
    },
    {
        "id": "win11-chrome-intel",
        "ua": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"),
        "platform": "Win32",
        "ua_platform": "Windows",
        "ua_platform_version": "15.0.0",
        "brands": [
            {"brand": "Not A(Brand", "version": "99"},
            {"brand": "Google Chrome", "version": "132"},
            {"brand": "Chromium", "version": "132"},
        ],
        "hardware_concurrency": 12,
        "device_memory": 16,
        "webgl_vendor": "Google Inc. (Intel)",
        "webgl_renderer": ("ANGLE (Intel, Intel(R) UHD Graphics 770 Direct3D11 "
                           "vs_5_0 ps_5_0, D3D11)"),
        "languages": ["en-US", "en"],
        "locale": "en-US",
        "timezone": "America/Chicago",
        "screen": {"width": 1536, "height": 864, "depth": 24},
        "viewport": {"width": 1536, "height": 731},
    },
    {
        "id": "macos-chrome",
        "ua": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"),
        "platform": "MacIntel",
        "ua_platform": "macOS",
        "ua_platform_version": "14.5.0",
        "brands": [
            {"brand": "Not(A:Brand", "version": "99"},
            {"brand": "Google Chrome", "version": "133"},
            {"brand": "Chromium", "version": "133"},
        ],
        "hardware_concurrency": 10,
        "device_memory": 16,
        "webgl_vendor": "Google Inc. (Apple)",
        "webgl_renderer": "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)",
        "languages": ["en-US", "en"],
        "locale": "en-US",
        "timezone": "America/Los_Angeles",
        "screen": {"width": 1728, "height": 1117, "depth": 30},
        "viewport": {"width": 1728, "height": 1000},
    },
]


def get_profile(index: int) -> dict:
    return PROFILES[index % len(PROFILES)]


def build_init_js(p: dict) -> str:
    """Return a JS init script that makes the headless browser's JS environment
    consistent with profile *p* and removes the standard automation tells."""
    import json as _json
    brands = _json.dumps(p["brands"])
    full_version_list = _json.dumps([
        {"brand": b["brand"], "version": f'{b["version"]}.0.0.0'} for b in p["brands"]
    ])
    languages = _json.dumps(p["languages"])
    return f"""
(function() {{
  try {{
    // webdriver tell
    Object.defineProperty(navigator, 'webdriver', {{ get: () => undefined }});

    // platform / hardware consistency
    Object.defineProperty(navigator, 'platform', {{ get: () => {p["platform"]!r} }});
    Object.defineProperty(navigator, 'hardwareConcurrency', {{ get: () => {p["hardware_concurrency"]} }});
    Object.defineProperty(navigator, 'deviceMemory', {{ get: () => {p["device_memory"]} }});
    Object.defineProperty(navigator, 'languages', {{ get: () => {languages} }});
    Object.defineProperty(navigator, 'maxTouchPoints', {{ get: () => 0 }});

    // realistic plugin + mimeType set (headless has none → instant flag)
    const mkPlugin = (n, d) => ({{ name: n, description: d, filename: 'internal-pdf-viewer' }});
    const plugins = [
      mkPlugin('PDF Viewer', 'Portable Document Format'),
      mkPlugin('Chrome PDF Viewer', 'Portable Document Format'),
      mkPlugin('Chromium PDF Viewer', 'Portable Document Format'),
      mkPlugin('Microsoft Edge PDF Viewer', 'Portable Document Format'),
      mkPlugin('WebKit built-in PDF', 'Portable Document Format'),
    ];
    Object.defineProperty(navigator, 'plugins', {{ get: () => plugins }});

    // userAgentData (UA Client Hints) must match the UA string
    if (navigator.userAgentData) {{
      try {{
        Object.defineProperty(navigator, 'userAgentData', {{
          get: () => ({{
            brands: {brands},
            mobile: false,
            platform: {p["ua_platform"]!r},
            getHighEntropyValues: function(hints) {{
              return Promise.resolve({{
                architecture: 'x86',
                bitness: '64',
                brands: {brands},
                fullVersionList: {full_version_list},
                mobile: false,
                model: '',
                platform: {p["ua_platform"]!r},
                platformVersion: {p["ua_platform_version"]!r},
                uaFullVersion: {full_version_list}[1].version
              }});
            }}
          }})
        }});
      }} catch (e) {{}}
    }}

    // WebGL vendor/renderer — SwiftShader is the classic headless giveaway
    const patchGL = (proto) => {{
      if (!proto) return;
      const orig = proto.getParameter;
      proto.getParameter = function(p) {{
        if (p === 37445) return {p["webgl_vendor"]!r};   // UNMASKED_VENDOR_WEBGL
        if (p === 37446) return {p["webgl_renderer"]!r}; // UNMASKED_RENDERER_WEBGL
        return orig.call(this, p);
      }};
    }};
    if (window.WebGLRenderingContext)  patchGL(WebGLRenderingContext.prototype);
    if (window.WebGL2RenderingContext) patchGL(WebGL2RenderingContext.prototype);

    // window.chrome stub (present in real Chrome, absent in bare headless)
    if (!window.chrome) {{
      window.chrome = {{ runtime: {{}}, loadTimes: function(){{}}, csi: function(){{}}, app: {{}} }};
    }}

    // permissions.query for 'notifications' should report 'prompt', not 'denied'
    try {{
      const origQuery = window.navigator.permissions.query;
      window.navigator.permissions.query = (params) =>
        params && params.name === 'notifications'
          ? Promise.resolve({{ state: Notification.permission === 'default' ? 'prompt' : Notification.permission }})
          : origQuery(params);
    }} catch (e) {{}}
  }} catch (e) {{}}
}})();
"""
