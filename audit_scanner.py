"""
audit_scanner.py — Eagle Wi-Fi Audit
Gestion de la connexion SSH au WLANPi, exécution de iw scan, parsing et classification des APs.
Alain Daigle, CWNE #332 — Réseaux Eagle Inc.
"""

import re
import socket
import paramiko

# ---------------------------------------------------------------------------
# Tables de lookup
# ---------------------------------------------------------------------------

OUI_VENDOR_MAP = {
    # Cisco / Meraki
    '00:00:0c': 'Cisco', '00:50:56': 'Cisco', 'f8:7b:20': 'Cisco',
    'b8:38:61': 'Cisco', '70:69:5a': 'Cisco', 'f4:cf:e2': 'Cisco',
    '00:26:cb': 'Cisco', '84:b8:02': 'Cisco', 'e8:65:d4': 'Cisco',
    '00:1a:a1': 'Cisco Meraki', 'e0:cb:bc': 'Cisco Meraki', '88:15:44': 'Cisco Meraki',
    '0c:8d:db': 'Cisco Meraki', '34:56:fe': 'Cisco Meraki',
    # Aruba / HPE
    '00:0b:86': 'Aruba', '00:1a:1e': 'Aruba', '18:64:72': 'Aruba',
    '6c:f3:7f': 'Aruba', '9c:1c:12': 'Aruba', 'd8:c7:c8': 'Aruba',
    'ac:a3:1e': 'Aruba', '94:b4:0f': 'Aruba', 'f0:5c:19': 'Aruba',
    # Ubiquiti
    '00:27:22': 'Ubiquiti', '04:18:d6': 'Ubiquiti', '24:a4:3c': 'Ubiquiti',
    '44:d9:e7': 'Ubiquiti', '68:72:51': 'Ubiquiti', '78:8a:20': 'Ubiquiti',
    'b4:fb:e4': 'Ubiquiti', 'dc:9f:db': 'Ubiquiti', 'f4:92:bf': 'Ubiquiti',
    '80:2a:a8': 'Ubiquiti', '18:e8:29': 'Ubiquiti', 'fc:ec:da': 'Ubiquiti',
    # Ruckus / CommScope
    '00:13:92': 'Ruckus', '24:c9:a1': 'Ruckus', '54:3d:37': 'Ruckus',
    'e8:10:98': 'Ruckus', 'c4:01:7c': 'Ruckus', '00:25:c4': 'Ruckus',
    # Juniper / Mist
    '28:d0:ea': 'Juniper/Mist', '40:a6:77': 'Juniper/Mist', '5c:5b:35': 'Juniper/Mist',
    # Extreme Networks / Aerohive
    '00:19:77': 'Extreme', 'a8:39:44': 'Extreme', '5c:0e:8b': 'Extreme',
    '28:99:3a': 'Extreme',
    # Fortinet
    '00:09:0f': 'Fortinet', '00:0c:e6': 'Fortinet', '08:5b:0e': 'Fortinet',
    # Apple
    '00:03:93': 'Apple', '00:0a:27': 'Apple', '00:0a:95': 'Apple',
    '00:1c:b3': 'Apple', '34:15:9e': 'Apple', '3c:07:54': 'Apple',
    'a4:c3:61': 'Apple', 'f0:18:98': 'Apple',
    # TP-Link
    '00:27:19': 'TP-Link', '14:cc:20': 'TP-Link', '50:fa:84': 'TP-Link',
    'a0:f3:c1': 'TP-Link', 'c0:25:e9': 'TP-Link', '54:af:97': 'TP-Link',
    # Netgear
    '00:09:5b': 'Netgear', '00:14:6c': 'Netgear', '20:4e:7f': 'Netgear',
    'a0:40:a0': 'Netgear', 'b0:39:56': 'Netgear',
    # Asus
    '00:0c:6e': 'Asus', '00:1a:92': 'Asus', '10:bf:48': 'Asus',
    'ac:9e:17': 'Asus', 'f4:6d:04': 'Asus',
    # Linksys / Belkin
    '00:06:25': 'Linksys', '00:0c:41': 'Linksys', '00:18:39': 'Linksys',
    '00:1c:10': 'Linksys',
    # Zyxel
    '00:13:49': 'Zyxel', '00:a0:c5': 'Zyxel', '1c:74:0d': 'Zyxel',
    # MikroTik
    '00:0c:42': 'MikroTik', '18:fd:74': 'MikroTik', '48:8f:5a': 'MikroTik',
    # Samsung
    '00:12:47': 'Samsung', '34:14:5f': 'Samsung', '8c:71:f8': 'Samsung',
    # Huawei
    '00:25:9e': 'Huawei', '04:75:03': 'Huawei', '48:46:fb': 'Huawei',
    '54:89:98': 'Huawei', 'ac:85:3d': 'Huawei',
}

RISK_ORDER = ['CRITIQUE', 'ÉLEVÉ', 'MOYEN', 'BON', 'EXCELLENT']


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def freq_to_band(freq: int) -> str:
    """Convertit une fréquence MHz en bande Wi-Fi."""
    if freq < 3000:
        return '2,4 GHz'
    elif freq < 5925:
        return '5 GHz'
    else:
        return '6 GHz'


def freq_to_channel(freq: int) -> int:
    """Convertit une fréquence MHz en numéro de canal."""
    if freq < 3000:
        # 2.4 GHz : canal 1 = 2412 MHz, pas de 5 MHz
        return (freq - 2412) // 5 + 1
    elif freq < 5925:
        # 5 GHz : canal 36 = 5180 MHz, pas de 5 MHz
        return (freq - 5180) // 5 + 36
    else:
        # 6 GHz : canal 1 = 5955 MHz, pas de 5 MHz
        ch = (freq - 5955) // 5 + 1
        return ch if ch > 0 else 1


def lookup_vendor(bssid: str) -> str:
    """Retourne le fabricant depuis les 3 premiers octets du BSSID."""
    if not bssid or len(bssid) < 8:
        return 'Inconnu'
    oui = bssid[:8].lower()
    vendor = OUI_VENDOR_MAP.get(oui, '')
    if vendor:
        return vendor
    # Essai avec les 2 premiers octets (rare mais utile pour certains blocs)
    oui2 = bssid[:5].lower()
    for key, val in OUI_VENDOR_MAP.items():
        if key.startswith(oui2):
            return val
    return 'Inconnu'


# ---------------------------------------------------------------------------
# Classe principale
# ---------------------------------------------------------------------------

class WLANPiScanner:
    """Gère la connexion SSH au WLANPi et l'exécution/parsing de iw scan."""

    def __init__(self, host: str, username: str = 'wlanpi', password: str = 'wlanpi',
                 iface: str = 'wlan1', port: int = 22):
        self.host = host
        self.username = username
        self.password = password
        self.iface = iface
        self.port = port
        self._client: paramiko.SSHClient | None = None

    # ------------------------------------------------------------------
    # Connexion / déconnexion
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """Établit la connexion SSH. Retourne True si succès."""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )
            self._client = client
            return True
        except Exception:
            self._client = None
            return False

    def disconnect(self):
        """Ferme la connexion SSH proprement."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def is_connected(self) -> bool:
        """Vérifie si la connexion SSH est active."""
        if self._client is None:
            return False
        transport = self._client.get_transport()
        return transport is not None and transport.is_active()

    # ------------------------------------------------------------------
    # Scan — capture passive en mode monitor (wlanpi0)
    # ------------------------------------------------------------------

    # Canaux 2,4 GHz (1-13), 5 GHz (36-177 pas de 4), 6 GHz principaux
    CHANNELS_2G = list(range(1, 14))
    CHANNELS_5G = [36, 40, 44, 48, 52, 56, 60, 64,
                   100, 104, 108, 112, 116, 120, 124, 128,
                   132, 136, 140, 144, 149, 153, 157, 161, 165]
    CHANNELS_6G = [1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45,
                   49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93]
    DWELL_MS = 400   # ms par canal

    def run_scan(self) -> list[dict]:
        """
        Scan actif via `iw dev wlan0 scan` (interface managed).
        Couvre 2,4 GHz + 5 GHz sans problème de channel hopping.
        Parse la sortie iw pour extraire SSID, sécurité, canal, RSSI.
        """
        import time

        if not self.is_connected():
            raise RuntimeError('Non connecté au WLANPi')

        managed_iface = self._detect_managed_iface() or 'wlan0'

        _, stdout, _ = self._client.exec_command(
            f'sudo /sbin/iw dev {managed_iface} scan 2>/dev/null',
            timeout=30,
        )
        raw_output = stdout.read().decode('utf-8', errors='replace')

        aps = self._parse_iw_scan(raw_output)

        # Dédupliquer par BSSID (garder le meilleur RSSI)
        all_aps: dict[str, dict] = {}
        for ap in aps:
            bssid = ap['bssid']
            if bssid not in all_aps or ap['rssi'] > all_aps[bssid]['rssi']:
                all_aps[bssid] = ap

        result = [self._classify(ap) for ap in all_aps.values()]
        return sorted(result, key=lambda x: RISK_ORDER.index(x['risk']))

    def _parse_iw_scan(self, output: str) -> list[dict]:
        """
        Parse la sortie de `iw dev wlan0 scan`.
        Extrait BSSID, SSID, fréquence, signal, RSN/WPA/WPS.
        Retourne une liste de dicts bruts (sans classification).
        """
        aps = []
        current: dict = {}

        def _flush(ap: dict) -> None:
            if ap.get('bssid'):
                aps.append(ap)

        for line in output.splitlines():
            # Nouveau BSS
            m = re.match(r'^BSS\s+([0-9a-fA-F:]{17})', line)
            if m:
                _flush(current)
                current = {
                    'bssid': m.group(1).upper(),
                    'ssid': '',
                    'freq': 0,
                    'channel': 0,
                    'band': '2,4 GHz',
                    'rssi': -100,
                    'has_rsn': False,
                    'has_wpa': False,
                    'wps': False,
                    'rsn_akms': '',
                    'rsn_pcs': '',
                    'rsn_caps_val': 0,
                    'wpa_akms': '',
                    'wpa_ucs': '',
                    'privacy': False,
                }
                continue

            if not current:
                continue

            line_s = line.strip()

            # Fréquence
            m = re.match(r'freq:\s+([\d.]+)', line_s)
            if m:
                current['freq'] = int(float(m.group(1)))
                current['channel'] = freq_to_channel(current['freq'])
                current['band'] = freq_to_band(current['freq'])
                continue

            # Signal
            m = re.match(r'signal:\s+([-\d.]+)', line_s)
            if m:
                current['rssi'] = int(float(m.group(1)))
                continue

            # SSID
            m = re.match(r'SSID:\s*(.*)', line_s)
            if m:
                current['ssid'] = m.group(1).strip()
                continue

            # Privacy (capability)
            if 'capability:' in line_s and 'Privacy' in line_s:
                current['privacy'] = True
                continue

            # RSN
            if line_s == 'RSN:':
                current['has_rsn'] = True
                continue
            m = re.match(r'\* Authentication suites:\s*(.*)', line_s)
            if m and current.get('has_rsn'):
                current['rsn_akms'] = m.group(1).upper()
                continue
            m = re.match(r'\* Pairwise ciphers:\s*(.*)', line_s)
            if m and current.get('has_rsn') and not current.get('rsn_pcs'):
                current['rsn_pcs'] = m.group(1).upper()
                continue
            m = re.match(r'\* Capabilities:.*\((0x[0-9a-fA-F]+)\)', line_s)
            if m and current.get('has_rsn'):
                try:
                    current['rsn_caps_val'] = int(m.group(1), 16)
                except ValueError:
                    pass
                continue

            # WPA (vendor IE)
            if 'WPA:' in line_s or (line_s.startswith('* Version: 1') and not current.get('has_rsn')):
                current['has_wpa'] = True
                continue
            if current.get('has_wpa') and not current.get('has_rsn'):
                m = re.match(r'\* Authentication suites:\s*(.*)', line_s)
                if m:
                    current['wpa_akms'] = m.group(1).upper()
                    continue
                m = re.match(r'\* Unicast ciphers:\s*(.*)', line_s)
                if m:
                    current['wpa_ucs'] = m.group(1).upper()
                    continue

            # WPS
            if 'Wi-Fi Protected Setup' in line_s or 'WPS:' in line_s:
                current['wps'] = True
                continue

        _flush(current)

        # Convertir vers le format attendu par _parse_tshark_fields → _classify
        result = []
        for ap in aps:
            freq = ap['freq']
            channel = ap['channel']
            band = ap['band']
            rssi = ap['rssi']
            has_rsn = ap['has_rsn']
            has_wpa = ap['has_wpa']
            wps = ap['wps']
            has_privacy = ap['privacy']
            rsn_akms_up = ap['rsn_akms']
            rsn_pcs_up = ap['rsn_pcs']
            caps_val = ap['rsn_caps_val']
            wpa_akms_up = ap['wpa_akms']
            wpa_ucs_up = ap['wpa_ucs']

            # PMF
            pmf = 'Disabled'
            if caps_val & 0x0040:
                pmf = 'Required'
            elif caps_val & 0x0080:
                pmf = 'Optional'

            # Auth / cipher
            auth, cipher = self._classify_auth(
                has_rsn, has_wpa, has_privacy, wps,
                rsn_akms_up, rsn_pcs_up, wpa_akms_up, wpa_ucs_up, pmf,
            )

            result.append({
                'bssid': ap['bssid'],
                'ssid': ap['ssid'],
                'freq': freq,
                'channel': channel,
                'band': band,
                'rssi': rssi,
                'has_rsn': has_rsn,
                'has_wpa': has_wpa,
                'wps': wps,
                'pmf': pmf,
                'auth': auth,
                'cipher': cipher,
            })
        return result

    def _classify_auth(
        self,
        has_rsn: bool, has_wpa: bool, has_privacy: bool, wps: bool,
        rsn_akms_up: str, rsn_pcs_up: str,
        wpa_akms_up: str, wpa_ucs_up: str,
        pmf: str,
    ) -> tuple[str, str]:
        """Déduit auth et cipher depuis les flags RSN/WPA."""
        if has_rsn:
            if 'SAE' in rsn_akms_up and ('PSK' in rsn_akms_up or '802.1X' in rsn_akms_up):
                is_enterprise = '802.1X' in rsn_akms_up or 'EAP' in rsn_akms_up
                auth = 'WPA2/WPA3-Enterprise' if is_enterprise else 'WPA2/WPA3-Personal'
            elif 'SAE' in rsn_akms_up:
                auth = 'WPA3-SAE'
            elif 'OWE' in rsn_akms_up:
                auth = 'OWE'
            elif '802.1X' in rsn_akms_up or 'EAP' in rsn_akms_up:
                auth = 'WPA3-Enterprise' if pmf == 'Required' else 'WPA2-Enterprise'
            elif 'PSK' in rsn_akms_up:
                auth = 'WPA2-Personal'
            else:
                auth = 'WPA2-Personal'
            cipher = 'CCMP' if 'CCMP' in rsn_pcs_up else ('TKIP' if 'TKIP' in rsn_pcs_up else 'CCMP')
            if 'TKIP' in rsn_pcs_up and 'CCMP' not in rsn_pcs_up:
                auth = auth.replace('WPA2', 'WPA1') if 'WPA2' in auth else auth
        elif has_wpa:
            if '802.1X' in wpa_akms_up or 'EAP' in wpa_akms_up:
                auth = 'WPA1-Enterprise'
            else:
                auth = 'WPA1-Personal'
            cipher = 'TKIP' if 'TKIP' in wpa_ucs_up else 'CCMP'
            if 'TKIP' in wpa_ucs_up and 'CCMP' in wpa_ucs_up:
                cipher = 'TKIP/CCMP'
        elif has_privacy:
            auth = 'WEP / WEP'
            cipher = 'WEP'
        else:
            auth = 'Open'
            cipher = 'None'
        return auth, cipher

    def _detect_monitor_iface(self) -> str:
        """Retourne l'interface en mode monitor (wlanpi0 en priorité)."""
        _stdin, stdout, _stderr = self._client.exec_command(
            '/usr/sbin/iw dev 2>/dev/null', timeout=10
        )
        iw_out = stdout.read().decode('utf-8', errors='replace')
        current_iface = None
        for line in iw_out.splitlines():
            m = re.match(r'\s*Interface\s+(\S+)', line)
            if m:
                current_iface = m.group(1)
            if current_iface and re.search(r'type\s+monitor', line):
                return current_iface
        return self.iface

    def _detect_managed_iface(self) -> str | None:
        """Retourne l'interface en mode managed (wlan0) ou None."""
        _stdin, stdout, _stderr = self._client.exec_command(
            '/usr/sbin/iw dev 2>/dev/null', timeout=10
        )
        iw_out = stdout.read().decode('utf-8', errors='replace')
        current_iface = None
        for line in iw_out.splitlines():
            m = re.match(r'\s*Interface\s+(\S+)', line)
            if m:
                current_iface = m.group(1)
            if current_iface and re.search(r'type\s+managed', line):
                return current_iface
        return None

    def _parse_tshark_fields(self, output: str) -> list[dict]:
        """
        Parse la sortie tshark -T fields.
        Colonnes : sa, ssid, channel, freq, rsn.version, rsn.pcs, rsn.akms,
                   rsn.caps, wpa.version, wpa.mcs, wpa.ucs, wpa.akms,
                   capabilities.privacy, signal_dbm
        """
        aps = []
        for line in output.splitlines():
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 14:
                parts += [''] * (14 - len(parts))

            bssid       = parts[0].strip().upper()
            ssid_raw    = parts[1].strip()
            ch_str      = parts[2].strip()
            freq_str    = parts[3].strip()
            rsn_ver     = parts[4].strip()
            rsn_pcs     = parts[5].strip()   # pairwise cipher suite
            rsn_akms    = parts[6].strip()   # auth key mgmt suite
            rsn_caps    = parts[7].strip()   # RSN capabilities
            wpa_ver     = parts[8].strip()
            wpa_mcs     = parts[9].strip()
            wpa_ucs     = parts[10].strip()
            wpa_akms    = parts[11].strip()
            wps_ver     = ''                 # non disponible dans tshark 3.4.x
            privacy_str = parts[12].strip()  # bit Privacy des capabilities du beacon
            sig_str     = parts[13].strip()

            if not bssid or len(bssid) < 17:
                continue

            # SSID : tshark retourne les octets hex pour les SSIDs non-ASCII
            try:
                ssid = bytes.fromhex(ssid_raw.replace(':', '')).decode('utf-8', errors='replace') if ':' in ssid_raw else ssid_raw
            except Exception:
                ssid = ssid_raw

            # Fréquence / canal / bande
            try:
                freq = int(float(freq_str))
            except (ValueError, TypeError):
                freq = 0
            try:
                channel = int(ch_str)
            except (ValueError, TypeError):
                channel = freq_to_channel(freq) if freq else 0
            band = freq_to_band(freq) if freq else ('2,4 GHz' if channel <= 14 else '5 GHz')

            # RSSI
            try:
                rssi = int(float(sig_str))
            except (ValueError, TypeError):
                rssi = -100

            # Sécurité
            has_rsn = bool(rsn_ver)
            has_wpa = bool(wpa_ver)
            wps     = bool(wps_ver)
            # Bit Privacy des capabilities : présent sans RSN/WPA => WEP
            has_privacy = privacy_str.strip() in ('1', 'True', 'true')

            # Auth / cipher
            rsn_akms_up = rsn_akms.upper()
            wpa_akms_up = wpa_akms.upper()
            rsn_pcs_up  = rsn_pcs.upper()
            wpa_ucs_up  = wpa_ucs.upper()

            # PMF depuis RSN capabilities (bit 6 = MFP required, bit 7 = MFP capable)
            pmf = 'Disabled'
            try:
                caps_val = int(rsn_caps, 16) if rsn_caps else 0
                if caps_val & 0x0040:
                    pmf = 'Required'
                elif caps_val & 0x0080:
                    pmf = 'Optional'
            except (ValueError, TypeError):
                pass

            if not has_rsn and not has_wpa:
                auth, cipher = ('WEP', 'WEP') if has_privacy else ('Open', 'None')
            elif has_rsn:
                # Cipher
                if 'GCMP-256' in rsn_pcs_up or 'GCMP_256' in rsn_pcs_up:
                    cipher = 'GCMP'
                elif 'GCMP' in rsn_pcs_up:
                    cipher = 'GCMP'
                elif 'CCMP' in rsn_pcs_up:
                    cipher = 'CCMP'
                elif 'TKIP' in rsn_pcs_up:
                    cipher = 'TKIP'
                else:
                    cipher = 'CCMP'
                # Auth
                if 'SAE' in rsn_akms_up and ('802.1X' in rsn_akms_up or 'EAP' in rsn_akms_up):
                    auth = 'WPA3-Enterprise' if pmf == 'Required' else 'WPA2/WPA3-Enterprise'
                elif 'SAE' in rsn_akms_up and 'PSK' in rsn_akms_up:
                    auth = 'WPA2/WPA3-Personal'
                elif 'SAE' in rsn_akms_up:
                    auth = 'WPA3-SAE'
                elif 'OWE' in rsn_akms_up:
                    auth = 'OWE'
                elif '802.1X' in rsn_akms_up or 'EAP' in rsn_akms_up:
                    auth = 'WPA3-Enterprise' if pmf == 'Required' else 'WPA2-Enterprise'
                elif 'PSK' in rsn_akms_up:
                    # Mode mixte WPA1+WPA2-PSK : les clients WPA1/TKIP restent acceptés
                    auth = 'WPA2-Personal (mode mixte WPA1)' if has_wpa else 'WPA2-Personal'
                else:
                    auth = 'WPA2-Personal'
            else:
                # WPA1 seulement
                cipher = 'TKIP' if 'TKIP' in wpa_ucs_up else 'CCMP'
                auth = 'WPA2-Enterprise' if ('802.1X' in wpa_akms_up or 'EAP' in wpa_akms_up) else 'WPA1-Personal'

            ap = {
                'bssid':   bssid,
                'ssid':    ssid,
                'freq':    freq,
                'channel': channel,
                'band':    band,
                'rssi':    rssi,
                'auth':    auth,
                'cipher':  cipher,
                'pmf':     pmf,
                'wps':     wps,
                'vendor':  lookup_vendor(bssid),
            }
            aps.append(ap)
        return aps

    def _parse_iw_scan(self, raw: str) -> list[dict]:
        """
        Parse la sortie brute de `iw dev scan`.
        Retourne une liste de dicts avec les champs réseau bruts (sans classification).
        """
        aps: list[dict] = []
        current: dict | None = None

        # On garde une "section courante" (RSN ou WPA) pour les suites d'auth
        current_section: str | None = None  # 'RSN' | 'WPA' | None

        for line in raw.splitlines():
            # Nouvelle entrée BSS
            bss_match = re.match(r'^BSS ([0-9a-fA-F:]{17})', line)
            if bss_match:
                if current is not None:
                    aps.append(current)
                current = {
                    'bssid': bss_match.group(1).upper(),
                    'ssid': '',
                    'freq': 0,
                    'channel': 0,
                    'band': '2,4 GHz',
                    'rssi': -100,
                    'auth': 'Open',
                    'cipher': 'None',
                    'pmf': 'Disabled',
                    'wps': False,
                    # champs internes pour le parsing
                    '_has_rsn': False,
                    '_has_wpa': False,
                    '_rsn_auth': [],
                    '_wpa_auth': [],
                    '_rsn_cipher': '',
                    '_wpa_cipher': '',
                    '_rsn_pmf': '',
                    '_has_privacy': False,
                }
                current_section = None
                continue

            if current is None:
                continue

            stripped = line.strip()

            # Fréquence (peut être entier ou décimal ex: 2412.0)
            m = re.match(r'freq:\s*(\d+(?:\.\d+)?)', stripped)
            if m:
                freq = int(float(m.group(1)))
                current['freq'] = freq
                current['band'] = freq_to_band(freq)
                current['channel'] = freq_to_channel(freq)
                continue

            # SSID
            m = re.match(r'SSID:\s*(.*)', stripped)
            if m:
                current['ssid'] = m.group(1).strip()
                continue

            # Signal / RSSI
            m = re.match(r'signal:\s*(-?\d+(?:\.\d+)?)\s*dBm', stripped)
            if m:
                current['rssi'] = int(float(m.group(1)))
                continue

            # Bit Privacy des capabilities (ligne "capability: ESS Privacy ..." en iw scan)
            if stripped.startswith('capability:') and 'Privacy' in stripped:
                current['_has_privacy'] = True
                continue

            # Détection WPS
            if re.match(r'WPS:', stripped) or re.match(r'\*\s*Version:', stripped):
                if 'WPS' in line or current.get('_in_wps'):
                    current['wps'] = True

            # Début bloc WPS (multi-lignes)
            if stripped.startswith('WPS:'):
                current['wps'] = True
                continue

            # Début bloc RSN
            if stripped.startswith('RSN:'):
                current['_has_rsn'] = True
                current_section = 'RSN'
                continue

            # Début bloc WPA (WPA1 seulement — WPA2/WPA3 utilisent RSN)
            if re.match(r'WPA:\s*', stripped) and 'RSN' not in stripped:
                current['_has_wpa'] = True
                current_section = 'WPA'
                continue

            # Fin de section (nouvelle clé de haut niveau)
            if re.match(r'^[A-Za-z]', line) and not line.startswith('\t') and not line.startswith(' '):
                current_section = None

            # Parsing dans une section RSN ou WPA
            if current_section in ('RSN', 'WPA'):
                # Group cipher
                m = re.match(r'\*\s*Group cipher:\s*(\S+)', stripped)
                if m:
                    cipher_val = m.group(1).upper()
                    if current_section == 'RSN':
                        current['_rsn_cipher'] = cipher_val
                    else:
                        current['_wpa_cipher'] = cipher_val
                    continue

                # Pairwise cipher (on préfère pairwise sur group)
                m = re.match(r'\*\s*Pairwise ciphers?:\s*(.+)', stripped)
                if m:
                    ciphers = m.group(1).upper()
                    if current_section == 'RSN':
                        if 'CCMP-256' in ciphers or 'GCMP-256' in ciphers:
                            current['_rsn_cipher'] = 'GCMP'
                        elif 'GCMP' in ciphers:
                            current['_rsn_cipher'] = 'GCMP'
                        elif 'CCMP' in ciphers:
                            current['_rsn_cipher'] = 'CCMP'
                        elif 'TKIP' in ciphers:
                            current['_rsn_cipher'] = 'TKIP'
                    else:
                        if 'TKIP' in ciphers:
                            current['_wpa_cipher'] = 'TKIP'
                        elif 'CCMP' in ciphers:
                            current['_wpa_cipher'] = 'CCMP'
                    continue

                # Authentication suites
                m = re.match(r'\*\s*Authentication suites?:\s*(.+)', stripped)
                if m:
                    suites = m.group(1)
                    if current_section == 'RSN':
                        current['_rsn_auth'].append(suites)
                    else:
                        current['_wpa_auth'].append(suites)
                    continue

                # PMF (dans RSN)
                if current_section == 'RSN':
                    if 'MFP-required' in stripped or 'MFP required' in stripped:
                        current['_rsn_pmf'] = 'Required'
                    elif 'MFP-capable' in stripped or 'MFP capable' in stripped:
                        if current['_rsn_pmf'] != 'Required':
                            current['_rsn_pmf'] = 'Optional'

        # Dernier AP
        if current is not None:
            aps.append(current)

        # Post-traitement : dériver auth, cipher, pmf
        for ap in aps:
            self._finalize_ap(ap)

        # Lookup vendor
        for ap in aps:
            ap['vendor'] = lookup_vendor(ap['bssid'])

        return aps

    def _finalize_ap(self, ap: dict):
        """
        Convertit les champs internes (_has_rsn, _rsn_auth, etc.)
        en auth, cipher, pmf finaux.
        Supprime les champs temporaires.
        """
        has_rsn = ap.pop('_has_rsn', False)
        has_wpa = ap.pop('_has_wpa', False)
        rsn_auth_list = ap.pop('_rsn_auth', [])
        wpa_auth_list = ap.pop('_wpa_auth', [])
        rsn_cipher = ap.pop('_rsn_cipher', '')
        wpa_cipher = ap.pop('_wpa_cipher', '')
        rsn_pmf = ap.pop('_rsn_pmf', '')
        has_privacy = ap.pop('_has_privacy', False)

        rsn_auth_str = ' '.join(rsn_auth_list).upper()
        wpa_auth_str = ' '.join(wpa_auth_list).upper()

        # PMF
        if rsn_pmf:
            ap['pmf'] = rsn_pmf
        else:
            ap['pmf'] = 'Disabled'

        # Déterminer l'authentification
        if not has_rsn and not has_wpa:
            if has_privacy:
                ap['auth'] = 'WEP'
                ap['cipher'] = 'WEP'
            else:
                ap['auth'] = 'Open'
                ap['cipher'] = 'None'
        elif has_rsn:
            # WPA3 ?
            if 'SAE' in rsn_auth_str and 'IEEE 802.1X' in rsn_auth_str:
                ap['auth'] = 'WPA3-Enterprise' if rsn_pmf == 'Required' else 'WPA2/WPA3-Enterprise'
            elif 'SAE' in rsn_auth_str and 'PSK' in rsn_auth_str:
                ap['auth'] = 'WPA2/WPA3-Personal'
            elif 'SAE' in rsn_auth_str:
                ap['auth'] = 'WPA3-SAE'
            elif 'OWE' in rsn_auth_str:
                ap['auth'] = 'OWE'
            elif 'IEEE 802.1X' in rsn_auth_str or 'EAP' in rsn_auth_str:
                # WPA2-Enterprise ou WPA3-Enterprise
                if rsn_pmf == 'Required':
                    ap['auth'] = 'WPA3-Enterprise'
                else:
                    ap['auth'] = 'WPA2-Enterprise'
            elif 'PSK' in rsn_auth_str:
                # Mode mixte WPA1+WPA2-PSK : les clients WPA1/TKIP restent acceptés
                ap['auth'] = 'WPA2-Personal (mode mixte WPA1)' if has_wpa else 'WPA2-Personal'
            else:
                ap['auth'] = 'WPA2-Personal'

            # Cipher RSN
            if rsn_cipher in ('GCMP', 'GCMP-256'):
                ap['cipher'] = 'GCMP'
            elif rsn_cipher == 'CCMP':
                ap['cipher'] = 'CCMP'
            elif rsn_cipher == 'TKIP':
                ap['cipher'] = 'TKIP'
            else:
                ap['cipher'] = 'CCMP'  # défaut WPA2/WPA3

            # WPA1 seul (sans RSN mais avec WPA) ne devrait pas arriver ici
        elif has_wpa and not has_rsn:
            # WPA1 uniquement
            if 'IEEE 802.1X' in wpa_auth_str or 'EAP' in wpa_auth_str:
                ap['auth'] = 'WPA2-Enterprise'  # WPA1-Enterprise rare, on normalise
            else:
                ap['auth'] = 'WPA1-Personal'
            ap['cipher'] = wpa_cipher if wpa_cipher else 'TKIP'

    def _classify(self, ap: dict) -> dict:
        """
        Ajoute les champs risk, constat, wps_warning à un AP déjà parsé.
        """
        auth = ap.get('auth', 'Open')
        cipher = ap.get('cipher', 'None')
        pmf = ap.get('pmf', 'Disabled')
        wps = ap.get('wps', False)

        # Déterminer le niveau de risque
        if auth in ('Open', 'WEP') or cipher == 'WEP':
            risk = 'CRITIQUE'
            if auth == 'Open':
                constat = 'Réseau ouvert — aucun chiffrement, trafic interceptable en clair.'
            else:
                constat = 'WEP obsolète — clé récupérable en quelques minutes, chiffrement nul.'

        elif auth == 'WPA1-Personal' or cipher == 'TKIP':
            risk = 'ÉLEVÉ'
            if auth == 'WPA1-Personal':
                constat = 'WPA1-Personnel obsolète — vulnérable aux attaques TKIP et de dictionnaire.'
            else:
                constat = 'TKIP détecté — protocole obsolète, vulnérable aux attaques par rejeu.'

        elif auth == 'WPA2-Personal (mode mixte WPA1)':
            risk = 'ÉLEVÉ'
            constat = 'Mode mixte WPA1/WPA2-Personnel — les clients WPA1/TKIP restent acceptés, exposant le réseau aux attaques TKIP malgré la présence de WPA2.'

        elif auth == 'WPA2-Personal':
            risk = 'MOYEN'
            constat = 'WPA2-Personnel — vulnérable aux attaques par dictionnaire hors-ligne (PMKID/handshake).'

        elif auth in ('WPA2-Enterprise',):
            risk = 'BON'
            constat = 'WPA2-Entreprise — authentification 802.1X correcte; vérifier le certificat serveur.'

        elif auth == 'OWE':
            risk = 'BON'
            constat = 'OWE (Opportunistic Wireless Encryption) — chiffrement sans authentification, pas de MitM.'

        elif auth == 'WPA2/WPA3-Personal':
            risk = 'BON'
            constat = 'Mode de compatibilité WPA3 (RSN Override) — les clients WPA3 obtiennent SAE via RSN Override; les clients WPA2 restent vulnérables aux attaques par dictionnaire hors-ligne.'

        elif auth == 'WPA2/WPA3-Enterprise':
            risk = 'BON'
            constat = 'Mode de transition WPA2/WPA3-Entreprise — 802.1X avec PMF optionnel; migrer vers WPA3-Entreprise pour PMF obligatoire.'

        elif auth in ('WPA3-SAE', 'WPA3-Enterprise'):
            risk = 'EXCELLENT'
            if auth == 'WPA3-SAE':
                constat = 'WPA3-SAE — protection forward secrecy, résistant aux attaques hors-ligne.'
            else:
                constat = 'WPA3-Entreprise — authentification 802.1X avec PMF obligatoire, excellent niveau.'
        else:
            risk = 'MOYEN'
            constat = 'Sécurité indéterminée — vérification manuelle requise.'

        # Avertissement WPS
        wps_warning = wps and risk not in ('EXCELLENT',)
        if wps_warning:
            constat += ' WPS actif — vulnérable à l\'attaque Pixie Dust/brute-force PIN.'

        ap['risk'] = risk
        ap['constat'] = constat
        ap['wps_warning'] = wps_warning

        return ap
