import httpx
import re
import json
from bs4 import BeautifulSoup
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

class PkgeClient:
    def __init__(self, widget_key: str = None, aes_key: bytes = None, aes_iv: bytes = None):
        self.aes_key = aes_key or b'tsUlsDJ04cVBAK3D2HzegN48KrYHh2Wq'
        self.aes_iv = aes_iv or b'xX64KRVu21jsnUw0z03C1PQJkMuxy9l2'[:16]
        self.widget_key = widget_key or "POox85sYUXoAQ6iHPJqyjwcWuZRBHNuF"
        
        self.session = httpx.AsyncClient(headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        }, follow_redirects=True)
        self._update_api_session_headers()

    def _update_api_session_headers(self):
        self.api_session = httpx.AsyncClient(headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'X-Api-Widget-Key': self.widget_key,
            'Accept': 'application/json',
            'Origin': 'https://pkge.net',
            'Referer': 'https://pkge.net/'
        })

    def set_keys(self, widget_key: str = None, aes_key: bytes = None, aes_iv: bytes = None):
        """
        Manually override the encryption keys and widget key for quick fixes.
        """
        if widget_key: self.widget_key = widget_key
        if aes_key: self.aes_key = aes_key
        if aes_iv: self.aes_iv = aes_iv[:16]
        self._update_api_session_headers()

    async def init_keys(self):
        """
        Attempts to fetch fresh keys by scraping the latest parcel-view.js.
        Note: Because the JS is obfuscated, this uses heuristic regex and may break if the obfuscation changes.
        """
        js_url = "https://pkge.net/js/parcel-view.min.js"
        res_js = await self.session.get(js_url)
        js = res_js.text
        
        # 2. Extract Widget Key (Exactly 32 chars alphanumeric in a string literal)
        widget_match = re.search(r'["\']([a-zA-Z0-9]{32})["\']', js)
        if widget_match:
            self.widget_key = widget_match.group(1)
            
        # 3. Extract AES Keys
        # The obfuscator currently splits strings into pieces like 'a4actsUlsD' (skip 4 chars -> 'tsUlsD')
        all_strings = re.findall(r'["\'](.*?)["\']', js)
        parts = [s for s in all_strings if re.match(r'^[a-z]\d[a-zA-Z0-9]{6,20}$', s)]
        
        if parts:
            # Sort parts alphabetically (how the JS does it)
            parts.sort()
            
            # Since the obfuscator mixes widgetApiKeyParts and webApiKeyParts, 
            # we try to separate them. Historically, they form exactly two 32-byte strings.
            # As a best-effort, we evaluate all parts:
            decoded_parts = []
            for p in parts:
                skip = int(p[1])
                decoded_parts.append(p[skip:])
                
            # Fallback heuristic: Try to find combinations that equal exactly 32 bytes
            # For now, we will rely on manual overrides if this breaks drastically,
            # but we can rebuild using the current known groupings if they haven't changed the prefix letters.
            widget_prefixes = ('a', 'b', 'n', 'p', 'x3')
            web_prefixes = ('h', 'k', 't', 'x2')
            
            aes_key_str = ""
            aes_iv_str = ""
            
            for p in parts:
                skip = int(p[1])
                val = p[skip:]
                if p.startswith(widget_prefixes):
                    aes_key_str += val
                elif p.startswith(web_prefixes):
                    aes_iv_str += val
                    
            if len(aes_key_str) == 32:
                self.aes_key = aes_key_str.encode('utf-8')
            if len(aes_iv_str) >= 16:
                self.aes_iv = aes_iv_str.encode('utf-8')[:16]
                
        self._update_api_session_headers()
        return True

    def _decrypt_payload(self, b64_ciphertext: str) -> dict:
        ciphertext = b64decode(b64_ciphertext)
        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
        decrypted = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted, AES.block_size)
        return json.loads(decrypted.decode('utf-8'))

    async def _get_csrf_token(self, url: str) -> str:
        """Helper to fetch a CSRF token from a page"""
        res = await self.session.get(url)
        res.raise_for_status()
        soup = BeautifulSoup(res.text, 'html.parser')
        meta = soup.find('meta', {'name': 'csrf-token'})
        if meta and meta.get('content'):
            return meta['content']
        raise ValueError(f"CSRF token not found on {url}")

    def get_signup_url(self, email: str) -> str:
        return f"https://pkge.net/users/sign-up?login={httpx.QueryParams({'login': email})['login']}"

    async def login(self, email: str, password: str) -> bool:
        csrf_token = await self._get_csrf_token("https://pkge.net/")
        
        data = {
            "_csrf": csrf_token,
            "login": email,
            "password": password
        }
        
        res = await self.session.post("https://pkge.net/users/sign-in", data=data, headers={
            "Referer": "https://pkge.net/",
            "Origin": "https://pkge.net"
        })
        
        verify_res = await self.session.get("https://pkge.net/cabinet/parcels")
        has_identity = any("identity" in c for c in self.session.cookies.keys())
        
        if has_identity or verify_res.status_code == 200 and str(verify_res.url).endswith("/cabinet/parcels"):
            self.api_session.cookies.update(self.session.cookies)
            return True
        return False

    async def logout(self):
        try:
            csrf_token = await self._get_csrf_token("https://pkge.net/cabinet/parcels")
            await self.session.post("https://pkge.net/users/logout", data={"_csrf": csrf_token})
        except Exception:
            pass
        self.session.cookies.clear()
        self.api_session.cookies.clear()

    async def get_my_parcels(self) -> list:
        res = await self.session.get("https://pkge.net/cabinet/parcels")
        res.raise_for_status()
        
        soup = BeautifulSoup(res.text, 'html.parser')
        parcels = []
        
        for row in soup.find_all(['tr', 'div']):
            track_link = row.find('a', href=re.compile(r'/parcel/'))
            del_btn = row.find(['button', 'a'], onclick=re.compile(r'deleteTrackNumber\([\'"](\d+)[\'"]\)'))
            
            if track_link and del_btn:
                track_number = track_link.text.strip()
                match = re.search(r'deleteTrackNumber\([\'"](\d+)[\'"]\)', del_btn['onclick'])
                if match:
                    internal_id = match.group(1)
                    if not any(p['internal_id'] == internal_id for p in parcels):
                        parcels.append({
                            "internal_id": internal_id,
                            "track_number": track_number
                        })
        return parcels

    async def delete_parcel(self, internal_id: str) -> bool:
        csrf_token = await self._get_csrf_token("https://pkge.net/cabinet/parcels")
        url = f"https://pkge.net/cabinet/parcels/delete?id={internal_id}"
        res = await self.session.post(url, data={"_csrf": csrf_token}, headers={
            "Referer": "https://pkge.net/cabinet/parcels",
            "Origin": "https://pkge.net"
        })
        return res.status_code == 200

    async def get_tracking_initial(self, track_number: str) -> dict:
        url = f"https://pkge.net/parcel/{track_number}"
        res = await self.session.get(url)
        res.raise_for_status()
        
        match = re.search(r'new\s+parcelView\(\s*["\']([^"\']+)["\']\s*\)', res.text)
        if not match:
            raise ValueError("Could not find encrypted tracking payload on the page.")
        
        b64_ciphertext = match.group(1)
        return self._decrypt_payload(b64_ciphertext)

    async def request_update(self, track_number: str) -> dict:
        url = f"https://api.pkge.net/v1/packages/update?trackNumber={track_number}"
        res = await self.api_session.post(url)
        try:
            return res.json()
        except Exception:
            res.raise_for_status()
            return {"text": res.text}

    async def get_tracking_status(self, track_number: str, package_hash: str) -> dict:
        url = f"https://api.pkge.net/v1/packages/status/{track_number}/{package_hash}"
        res = await self.api_session.get(url)
        res.raise_for_status()
        data = res.json()
        
        if "payload" in data and data["payload"]:
            return self._decrypt_payload(data["payload"])
        return data
        
    async def close(self):
        await self.session.aclose()
        await self.api_session.aclose()
