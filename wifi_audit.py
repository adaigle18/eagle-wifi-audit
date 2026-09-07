"""
wifi_audit.py — Eagle Wi-Fi Audit
Application Flask principale d'audit Wi-Fi passif.
Alain Daigle, CWNE #332 — Réseaux Eagle Inc.
"""

import csv
import io
import os
import socket
import threading
import time
import datetime
import tempfile

from flask import Flask, jsonify, render_template, request, send_file

from audit_scanner import WLANPiScanner
from report_generator import generate_report

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
WLANPI_HOST = '169.254.42.1'
WLANPI_USER = 'wlanpi'
WLANPI_PASSWORD = 'Root1234'
WLANPI_IFACE = 'wlan1'
WLANPI_PORT = 22
REFRESH_INTERVAL = 60   # secondes entre scans automatiques
PROBE_INTERVAL = 10     # secondes entre tentatives de connexion WLANPi

# Mode démo : EAGLE_DEMO=1 python wifi_audit.py
DEMO_MODE = os.environ.get('EAGLE_DEMO', '').lower() in ('1', 'true', 'yes')

# ---------------------------------------------------------------------------
# Données de démonstration
# ---------------------------------------------------------------------------
_DEMO_NETWORKS = [
    # CRITIQUE — Open
    {
        'bssid': 'E8:65:D4:11:22:33', 'ssid': 'Guest_Cafe_FREE',
        'freq': 2437, 'channel': 6, 'band': '2,4 GHz', 'rssi': -62,
        'auth': 'Open', 'cipher': 'None', 'pmf': 'Disabled', 'wps': False,
        'vendor': 'Cisco',
        'risk': 'CRITIQUE',
        'constat': 'Réseau ouvert — aucun chiffrement, trafic interceptable en clair.',
        'wps_warning': False,
    },
    # CRITIQUE — WEP
    {
        'bssid': '00:14:6C:AA:BB:CC', 'ssid': 'OldOffice',
        'freq': 2412, 'channel': 1, 'band': '2,4 GHz', 'rssi': -75,
        'auth': 'WEP', 'cipher': 'WEP', 'pmf': 'Disabled', 'wps': False,
        'vendor': 'Netgear',
        'risk': 'CRITIQUE',
        'constat': 'WEP obsolète — clé récupérable en quelques minutes, chiffrement nul.',
        'wps_warning': False,
    },
    # CRITIQUE — Open + WPS
    {
        'bssid': '50:FA:84:DD:EE:FF', 'ssid': 'PrinterSetup',
        'freq': 2462, 'channel': 11, 'band': '2,4 GHz', 'rssi': -58,
        'auth': 'Open', 'cipher': 'None', 'pmf': 'Disabled', 'wps': True,
        'vendor': 'TP-Link',
        'risk': 'CRITIQUE',
        'constat': "Réseau ouvert — aucun chiffrement, trafic interceptable en clair. WPS actif — vulnérable à l'attaque Pixie Dust/brute-force PIN.",
        'wps_warning': True,
    },
    # ÉLEVÉ — WPA1-Personal
    {
        'bssid': '00:1A:A1:44:55:66', 'ssid': 'Entrepot_Vieux',
        'freq': 2432, 'channel': 5, 'band': '2,4 GHz', 'rssi': -71,
        'auth': 'WPA1-Personal', 'cipher': 'TKIP', 'pmf': 'Disabled', 'wps': False,
        'vendor': 'Cisco Meraki',
        'risk': 'ÉLEVÉ',
        'constat': 'WPA1-Personnel obsolète — vulnérable aux attaques TKIP et de dictionnaire.',
        'wps_warning': False,
    },
    # ÉLEVÉ — WPA2 + TKIP cipher + WPS
    {
        'bssid': '00:27:19:77:88:99', 'ssid': 'Bureau_2etage',
        'freq': 5180, 'channel': 36, 'band': '5 GHz', 'rssi': -68,
        'auth': 'WPA2-Personal', 'cipher': 'TKIP', 'pmf': 'Disabled', 'wps': True,
        'vendor': 'TP-Link',
        'risk': 'ÉLEVÉ',
        'constat': "TKIP détecté — protocole obsolète, vulnérable aux attaques par rejeu. WPS actif — vulnérable à l'attaque Pixie Dust/brute-force PIN.",
        'wps_warning': True,
    },
    # MOYEN — WPA2-Personal
    {
        'bssid': '04:18:D6:AB:CD:EF', 'ssid': 'Acme-Corp-WiFi',
        'freq': 5500, 'channel': 100, 'band': '5 GHz', 'rssi': -55,
        'auth': 'WPA2-Personal', 'cipher': 'CCMP', 'pmf': 'Disabled', 'wps': False,
        'vendor': 'Ubiquiti',
        'risk': 'MOYEN',
        'constat': 'WPA2-Personnel — vulnérable aux attaques par dictionnaire hors-ligne (PMKID/handshake).',
        'wps_warning': False,
    },
    # MOYEN — WPA2-Personal + WPS
    {
        'bssid': 'AC:9E:17:12:34:56', 'ssid': 'Maison_Voisin',
        'freq': 2437, 'channel': 6, 'band': '2,4 GHz', 'rssi': -80,
        'auth': 'WPA2-Personal', 'cipher': 'CCMP', 'pmf': 'Disabled', 'wps': True,
        'vendor': 'Asus',
        'risk': 'MOYEN',
        'constat': "WPA2-Personnel — vulnérable aux attaques par dictionnaire hors-ligne (PMKID/handshake). WPS actif — vulnérable à l'attaque Pixie Dust/brute-force PIN.",
        'wps_warning': True,
    },
    # BON — WPA2-Enterprise
    {
        'bssid': '6C:F3:7F:DE:AD:01', 'ssid': 'CorpNet-802.1X',
        'freq': 5240, 'channel': 48, 'band': '5 GHz', 'rssi': -50,
        'auth': 'WPA2-Enterprise', 'cipher': 'CCMP', 'pmf': 'Optional', 'wps': False,
        'vendor': 'Aruba',
        'risk': 'BON',
        'constat': 'WPA2-Entreprise — authentification 802.1X correcte; vérifier le certificat serveur.',
        'wps_warning': False,
    },
    # BON — OWE
    {
        'bssid': '44:D9:E7:BE:EF:02', 'ssid': 'Guest_OWE',
        'freq': 5745, 'channel': 149, 'band': '5 GHz', 'rssi': -61,
        'auth': 'OWE', 'cipher': 'CCMP', 'pmf': 'Required', 'wps': False,
        'vendor': 'Ubiquiti',
        'risk': 'BON',
        'constat': 'OWE (Opportunistic Wireless Encryption) — chiffrement sans authentification, pas de MitM.',
        'wps_warning': False,
    },
    # EXCELLENT — WPA3-SAE
    {
        'bssid': '5C:5B:35:CA:FE:03', 'ssid': 'SecureNet-WPA3',
        'freq': 5765, 'channel': 153, 'band': '5 GHz', 'rssi': -48,
        'auth': 'WPA3-SAE', 'cipher': 'GCMP', 'pmf': 'Required', 'wps': False,
        'vendor': 'Juniper/Mist',
        'risk': 'EXCELLENT',
        'constat': 'WPA3-SAE — protection forward secrecy, résistant aux attaques hors-ligne.',
        'wps_warning': False,
    },
    # EXCELLENT — WPA3-SAE (2,4 GHz)
    {
        'bssid': '18:64:72:FA:CE:04', 'ssid': 'SecureNet-WPA3',
        'freq': 2412, 'channel': 1, 'band': '2,4 GHz', 'rssi': -54,
        'auth': 'WPA3-SAE', 'cipher': 'CCMP', 'pmf': 'Required', 'wps': False,
        'vendor': 'Aruba',
        'risk': 'EXCELLENT',
        'constat': 'WPA3-SAE — protection forward secrecy, résistant aux attaques hors-ligne.',
        'wps_warning': False,
    },
    # EXCELLENT — WPA3-Enterprise
    {
        'bssid': '28:D0:EA:B0:0B:05', 'ssid': 'Enterprise-WPA3',
        'freq': 5180, 'channel': 36, 'band': '5 GHz', 'rssi': -45,
        'auth': 'WPA3-Enterprise', 'cipher': 'GCMP', 'pmf': 'Required', 'wps': False,
        'vendor': 'Juniper/Mist',
        'risk': 'EXCELLENT',
        'constat': 'WPA3-Entreprise — authentification 802.1X avec PMF obligatoire, excellent niveau.',
        'wps_warning': False,
    },
    # BON — WPA2/WPA3-Personal (mode de transition)
    {
        'bssid': '9C:1C:12:CC:DD:06', 'ssid': 'Acme-WiFi',
        'freq': 5745, 'channel': 149, 'band': '5 GHz', 'rssi': -52,
        'auth': 'WPA2/WPA3-Personal', 'cipher': 'CCMP', 'pmf': 'Optional', 'wps': False,
        'vendor': 'Aruba',
        'risk': 'BON',
        'constat': 'Mode de transition WPA2/WPA3 — les clients WPA3 obtiennent SAE; les clients WPA2 restent vulnérables aux attaques par dictionnaire hors-ligne.',
        'wps_warning': False,
    },
    # BON — WPA2/WPA3-Enterprise (mode de transition)
    {
        'bssid': 'AC:A3:1E:EE:FF:07', 'ssid': 'CorpNet-Secure',
        'freq': 5500, 'channel': 100, 'band': '5 GHz', 'rssi': -57,
        'auth': 'WPA2/WPA3-Enterprise', 'cipher': 'CCMP', 'pmf': 'Optional', 'wps': False,
        'vendor': 'Aruba',
        'risk': 'BON',
        'constat': 'Mode de transition WPA2/WPA3-Entreprise — 802.1X avec PMF optionnel; migrer vers WPA3-Entreprise pour PMF obligatoire.',
        'wps_warning': False,
    },
]

# ---------------------------------------------------------------------------
# État global
# ---------------------------------------------------------------------------
_cache: list[dict] = []
_lock = threading.Lock()

_wlanpi_status = {
    'connected': False,
    'host': WLANPI_HOST,
    'last_scan': None,
    'ap_count': 0,
}
_status_lock = threading.Lock()

_scanner: WLANPiScanner | None = None
_scanner_lock = threading.Lock()

_scan_event = threading.Event()   # déclenche un scan immédiat

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)


# ---------------------------------------------------------------------------
# Threads de fond
# ---------------------------------------------------------------------------

def _do_scan():
    """Exécute un scan et met à jour _cache et _wlanpi_status."""
    global _scanner
    with _scanner_lock:
        scanner = _scanner

    if scanner is None:
        return

    try:
        if not scanner.is_connected():
            if not scanner.connect():
                with _status_lock:
                    _wlanpi_status['connected'] = False
                return

        networks = scanner.run_scan()

        with _lock:
            _cache.clear()
            _cache.extend(networks)

        with _status_lock:
            _wlanpi_status['connected'] = True
            _wlanpi_status['last_scan'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            _wlanpi_status['ap_count'] = len(networks)

    except Exception as e:
        app.logger.error(f'Erreur lors du scan WLANPi: {e}')
        with _status_lock:
            _wlanpi_status['connected'] = False
        # Réinitialiser le scanner
        with _scanner_lock:
            if _scanner is not None:
                try:
                    _scanner.disconnect()
                except Exception:
                    pass
            _scanner = None


def _load_demo_data():
    """Charge les données de démonstration dans le cache."""
    from audit_scanner import RISK_ORDER
    demo = sorted(_DEMO_NETWORKS, key=lambda x: RISK_ORDER.index(x['risk']))
    with _lock:
        _cache.clear()
        _cache.extend(demo)
    with _status_lock:
        _wlanpi_status['connected'] = True
        _wlanpi_status['host'] = 'MODE DÉMO'
        _wlanpi_status['last_scan'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        _wlanpi_status['ap_count'] = len(demo)
    app.logger.info(f'Mode démo actif — {len(demo)} APs chargés.')


def background_refresher():
    """Thread daemon : déclenche un scan toutes les REFRESH_INTERVAL secondes si connecté."""
    if DEMO_MODE:
        return  # Pas de refresh automatique en démo

    while True:
        # Attendre soit l'événement de scan immédiat, soit le délai
        triggered = _scan_event.wait(timeout=REFRESH_INTERVAL)
        if triggered:
            _scan_event.clear()

        with _status_lock:
            connected = _wlanpi_status['connected']

        if connected:
            _do_scan()


def wlanpi_prober():
    """
    Thread daemon : vérifie TCP port 22 toutes les PROBE_INTERVAL secondes.
    À la première connexion, instancie WLANPiScanner et déclenche un scan immédiat.
    Inactif en mode démo.
    """
    if DEMO_MODE:
        return
    global _scanner
    first_connection = True

    while True:
        # Test TCP port 22
        reachable = False
        try:
            with socket.create_connection((WLANPI_HOST, WLANPI_PORT), timeout=3):
                reachable = True
        except (OSError, socket.timeout):
            reachable = False

        if reachable:
            with _scanner_lock:
                scanner_exists = _scanner is not None

            if not scanner_exists:
                # Créer et connecter le scanner
                new_scanner = WLANPiScanner(
                    host=WLANPI_HOST,
                    username=WLANPI_USER,
                    password=WLANPI_PASSWORD,
                    iface=WLANPI_IFACE,
                    port=WLANPI_PORT,
                )
                if new_scanner.connect():
                    with _scanner_lock:
                        _scanner = new_scanner
                    with _status_lock:
                        _wlanpi_status['connected'] = True
                    app.logger.info(f'WLANPi connecté : {WLANPI_HOST}')
                    # Déclencher un scan immédiat
                    _scan_event.set()
                else:
                    app.logger.warning(f'WLANPi atteignable mais SSH échoué : {WLANPI_HOST}')
                    with _status_lock:
                        _wlanpi_status['connected'] = False
            else:
                # Scanner existe — vérifier qu'il est toujours connecté
                with _scanner_lock:
                    s = _scanner
                if s and not s.is_connected():
                    with _status_lock:
                        _wlanpi_status['connected'] = False
                    with _scanner_lock:
                        _scanner = None
        else:
            # WLANPi non atteignable
            with _scanner_lock:
                if _scanner is not None:
                    try:
                        _scanner.disconnect()
                    except Exception:
                        pass
                    _scanner = None
            with _status_lock:
                _wlanpi_status['connected'] = False

        time.sleep(PROBE_INTERVAL)


# ---------------------------------------------------------------------------
# Routes Flask
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/scan')
def api_scan():
    with _lock:
        networks = list(_cache)
    with _status_lock:
        status = dict(_wlanpi_status)
    return jsonify({'networks': networks, 'status': status})


@app.route('/api/refresh', methods=['POST'])
def api_refresh():
    """Déclenche un rescan immédiat dans le thread de fond."""
    if DEMO_MODE:
        _load_demo_data()
        return jsonify({'ok': True, 'demo': True})

    with _status_lock:
        connected = _wlanpi_status['connected']

    if not connected:
        return jsonify({'ok': False, 'error': 'WLANPi non connecté'})

    _scan_event.set()
    return jsonify({'ok': True})


@app.route('/api/status')
def api_status():
    with _status_lock:
        status = dict(_wlanpi_status)
    return jsonify(status)


@app.route('/api/report', methods=['POST'])
def api_report():
    """Génère le rapport .docx et le retourne en téléchargement."""
    data = request.get_json(force=True) or {}

    metadata = {
        'client':       data.get('client', 'Client'),
        'site':         data.get('site', 'Site'),
        'date':         data.get('date', datetime.date.today().isoformat()),
        'mandat':       data.get('mandat', ''),
        'auditeur':     data.get('auditeur', ''),
        'iface':        WLANPI_IFACE,
        'duration_min': data.get('duration_min', 60),
    }

    with _lock:
        networks = list(_cache)

    if not networks:
        return jsonify({'error': 'Aucun réseau en cache — effectuer un scan d\'abord.'}), 400

    # Filtrer sur les SSIDs sélectionnés si fournis
    selected_ssids = data.get('selected_ssids')
    if selected_ssids:
        networks = [n for n in networks if n.get('ssid', '') in selected_ssids]

    if not networks:
        return jsonify({'error': 'Aucun réseau correspondant aux SSIDs sélectionnés.'}), 400

    # Générer dans un fichier temporaire
    tmp = tempfile.NamedTemporaryFile(suffix='.docx', delete=False)
    tmp.close()
    try:
        generate_report(networks, metadata, tmp.name)
        client_safe = ''.join(c for c in metadata['client'] if c.isalnum() or c in ' _-')[:30]
        date_str = metadata['date'].replace('-', '')
        filename = f'Eagle_WiFi_Audit_{client_safe}_{date_str}.docx'
        return send_file(
            tmp.name,
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            as_attachment=True,
            download_name=filename,
        )
    except Exception as e:
        app.logger.error(f'Erreur génération rapport: {e}')
        return jsonify({'error': str(e)}), 500
    finally:
        # Nettoyage différé (send_file streame le fichier)
        def _cleanup():
            time.sleep(5)
            try:
                os.unlink(tmp.name)
            except Exception:
                pass
        threading.Thread(target=_cleanup, daemon=True).start()


@app.route('/api/export/csv')
def api_export_csv():
    """Exporte le cache en CSV (filtré sur selected_ssids si fourni en query param)."""
    with _lock:
        networks = list(_cache)

    selected_ssids = request.args.getlist('ssid')
    if selected_ssids:
        networks = [n for n in networks if n.get('ssid', '') in selected_ssids]

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)

    headers = [
        'RISQUE', 'SSID', 'BSSID', 'SECURITE', 'CHIFFREMENT',
        'PMF', 'WPS', 'CANAL', 'BANDE', 'RSSI', 'VENDOR', 'CONSTAT'
    ]
    writer.writerow(headers)

    for ap in networks:
        wps_val = 'Oui' if ap.get('wps') else 'Non'
        writer.writerow([
            ap.get('risk', ''),
            ap.get('ssid', '') or '[hidden]',
            ap.get('bssid', ''),
            ap.get('auth', ''),
            ap.get('cipher', ''),
            ap.get('pmf', ''),
            wps_val,
            ap.get('channel', ''),
            ap.get('band', ''),
            ap.get('rssi', ''),
            ap.get('vendor', ''),
            ap.get('constat', ''),
        ])

    output.seek(0)
    date_str = datetime.date.today().isoformat().replace('-', '')
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8-sig')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'Eagle_WiFi_Audit_{date_str}.csv',
    )


# ---------------------------------------------------------------------------
# Démarrage
# ---------------------------------------------------------------------------

def _start_background_threads():
    t1 = threading.Thread(target=background_refresher, daemon=True, name='refresher')
    t1.start()
    t2 = threading.Thread(target=wlanpi_prober, daemon=True, name='prober')
    t2.start()


if __name__ == '__main__':
    if DEMO_MODE:
        _load_demo_data()
    _start_background_threads()
    app.run(host='127.0.0.1', port=5002, debug=False)
