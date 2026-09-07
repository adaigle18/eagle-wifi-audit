"""
report_generator.py — Eagle Wi-Fi Audit
Génération du rapport Word (.docx) de posture Wi-Fi.
Alain Daigle, CWNE #332 — Réseaux Eagle Inc.
"""

import datetime
import io
from collections import Counter

from docx import Document
from docx.shared import Pt, RGBColor, Inches, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

# ---------------------------------------------------------------------------
# Constantes visuelles
# ---------------------------------------------------------------------------

RISK_ORDER = ['CRITIQUE', 'ÉLEVÉ', 'MOYEN', 'BON', 'EXCELLENT']

RISK_COLORS = {
    'CRITIQUE':  RGBColor(0xC0, 0x20, 0x20),   # rouge
    'ÉLEVÉ':     RGBColor(0xE0, 0x70, 0x00),   # orange
    'MOYEN':     RGBColor(0x20, 0x60, 0xA0),   # bleu
    'BON':       RGBColor(0x20, 0x80, 0x40),   # vert foncé
    'EXCELLENT': RGBColor(0x10, 0x60, 0x20),   # vert
}

RISK_BG = {
    'CRITIQUE':  'C02020',
    'ÉLEVÉ':     'E07000',
    'MOYEN':     '2060A0',
    'BON':       '208040',
    'EXCELLENT': '106020',
}

RISK_SIGNIFICATION = {
    'CRITIQUE':  'Absence de chiffrement ou protocole cassé — correction immédiate.',
    'ÉLEVÉ':     'Protocole obsolète (WPA1/TKIP) — migration urgente requise.',
    'MOYEN':     'WPA2-Personnel — risque d\'attaque par dictionnaire hors-ligne.',
    'BON':       'WPA2-Entreprise ou OWE — niveau acceptable, améliorations possibles.',
    'EXCELLENT': 'WPA3 — meilleure protection disponible, forward secrecy.',
}

HEADER_BG = '2C3E50'
HEADER_TEXT = RGBColor(0xFF, 0xFF, 0xFF)
META_HEADER_BG = '34495E'
LIGHT_GRAY = 'D5D8DC'
VERY_LIGHT_GRAY = 'F2F3F4'


# ---------------------------------------------------------------------------
# Helpers XML / mise en forme
# ---------------------------------------------------------------------------

def _set_cell_bg(cell, hex_color: str):
    """Applique une couleur de fond à une cellule Word."""
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), hex_color)
    tcPr.append(shd)


def _set_cell_borders(cell, border_color: str = 'FFFFFF', size: int = 4):
    """Applique des bordures blanches légères à une cellule."""
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    borders = OxmlElement('w:tcBorders')
    for side in ('top', 'left', 'bottom', 'right'):
        el = OxmlElement(f'w:{side}')
        el.set(qn('w:val'), 'single')
        el.set(qn('w:sz'), str(size))
        el.set(qn('w:space'), '0')
        el.set(qn('w:color'), border_color)
        borders.append(el)
    tcPr.append(borders)


def _bold_run(para, text: str, size_pt: int = 11, color: RGBColor = None,
               align: str = None):
    """Ajoute un run gras à un paragraphe."""
    run = para.add_run(text)
    run.bold = True
    run.font.size = Pt(size_pt)
    if color:
        run.font.color.rgb = color
    if align:
        para.alignment = {
            'center': WD_ALIGN_PARAGRAPH.CENTER,
            'left': WD_ALIGN_PARAGRAPH.LEFT,
            'right': WD_ALIGN_PARAGRAPH.RIGHT,
        }.get(align, WD_ALIGN_PARAGRAPH.LEFT)
    return run


def _add_heading(doc: Document, text: str, level: int = 1):
    """Ajoute un titre stylisé."""
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(14)
    p.paragraph_format.space_after = Pt(4)
    run = p.add_run(text)
    run.bold = True
    if level == 1:
        run.font.size = Pt(13)
        run.font.color.rgb = RGBColor(0x2C, 0x3E, 0x50)
    elif level == 2:
        run.font.size = Pt(11)
        run.font.color.rgb = RGBColor(0x44, 0x62, 0x7A)
    # Ligne décorative
    border_para = doc.add_paragraph()
    border_para.paragraph_format.space_before = Pt(0)
    border_para.paragraph_format.space_after = Pt(6)
    pPr = border_para._p.get_or_add_pPr()
    pBdr = OxmlElement('w:pBdr')
    bottom = OxmlElement('w:bottom')
    bottom.set(qn('w:val'), 'single')
    bottom.set(qn('w:sz'), '6' if level == 1 else '4')
    bottom.set(qn('w:space'), '1')
    bottom.set(qn('w:color'), '2C3E50' if level == 1 else '7F8C8D')
    pBdr.append(bottom)
    pPr.append(pBdr)
    return p


def _add_body(doc: Document, text: str, italic: bool = False, size_pt: int = 10):
    """Ajoute un paragraphe de corps de texte."""
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(4)
    run = p.add_run(text)
    run.font.size = Pt(size_pt)
    run.italic = italic
    return p


def _set_table_style(table):
    """Applique un style de tableau simple."""
    table.style = 'Table Grid'


def _set_col_width(table, col_idx: int, width_cm: float):
    """Définit la largeur d'une colonne."""
    for row in table.rows:
        row.cells[col_idx].width = Cm(width_cm)


# ---------------------------------------------------------------------------
# Générateur principal
# ---------------------------------------------------------------------------

def generate_report(networks: list[dict], metadata: dict, output_path: str) -> str:
    """
    Génère le rapport Word complet.

    networks : liste d'APs classifiés (output de WLANPiScanner.run_scan())
    metadata : {client, site, date, mandat, iface, duration_min}
    output_path : chemin .docx de sortie

    Retourne output_path.
    """
    doc = Document()

    # Marges de page
    for section in doc.sections:
        section.top_margin = Cm(2.0)
        section.bottom_margin = Cm(2.0)
        section.left_margin = Cm(2.5)
        section.right_margin = Cm(2.0)

    # Pied de page
    _add_footer(doc)

    # -----------------------------------------------------------------------
    # EN-TÊTE — bannière + métadonnées
    # -----------------------------------------------------------------------
    _add_header_banner(doc)
    _add_metadata_table(doc, metadata)

    # -----------------------------------------------------------------------
    # SECTION 1 — Sommaire exécutif
    # -----------------------------------------------------------------------
    _add_heading(doc, '1. Sommaire exécutif')
    _add_executive_summary(doc, networks, metadata)

    # -----------------------------------------------------------------------
    # SECTION 2 — Portée et méthode
    # -----------------------------------------------------------------------
    _add_heading(doc, '2. Portée et méthode')
    _add_scope_section(doc, metadata)

    # -----------------------------------------------------------------------
    # SECTION 3 — Synthèse des constats
    # -----------------------------------------------------------------------
    _add_heading(doc, '3. Synthèse des constats')
    _add_summary_table(doc, networks)

    # -----------------------------------------------------------------------
    # SECTION 4 — Détail des réseaux
    # -----------------------------------------------------------------------
    _add_heading(doc, '4. Détail des réseaux observés')
    _add_networks_table(doc, networks)

    # -----------------------------------------------------------------------
    # SECTION 5 — Recommandations
    # -----------------------------------------------------------------------
    _add_heading(doc, '5. Recommandations prioritaires')
    _add_recommendations(doc, networks)

    # -----------------------------------------------------------------------
    # SECTION 6 — Limites de l'audit passif
    # -----------------------------------------------------------------------
    _add_heading(doc, '6. Limites de l\'audit passif')
    _add_limits_section(doc)

    # -----------------------------------------------------------------------
    # SECTION 7 — Force des clés
    # -----------------------------------------------------------------------
    _add_heading(doc, '7. Force des clés et résistance à l\'intrusion')
    _add_key_strength_section(doc)

    # -----------------------------------------------------------------------
    # Mention de confidentialité finale
    # -----------------------------------------------------------------------
    _add_confidentiality_notice(doc)

    doc.save(output_path)
    return output_path


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def _add_header_banner(doc: Document):
    """Bannière en-tête avec fond sombre."""
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = table.rows[0].cells[0]
    _set_cell_bg(cell, HEADER_BG)
    cell.width = Cm(16)

    cell.paragraphs[0].clear()
    p1 = cell.paragraphs[0]
    p1.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p1.paragraph_format.space_before = Pt(8)
    p1.paragraph_format.space_after = Pt(2)
    r1 = p1.add_run('RÉSEAUX EAGLE INC.')
    r1.bold = True
    r1.font.size = Pt(18)
    r1.font.color.rgb = HEADER_TEXT

    p2 = cell.add_paragraph()
    p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p2.paragraph_format.space_before = Pt(0)
    p2.paragraph_format.space_after = Pt(8)
    r2 = p2.add_run('Rapport de posture de la sécurité Wi-Fi')
    r2.font.size = Pt(11)
    r2.font.color.rgb = RGBColor(0xBD, 0xC3, 0xC7)

    doc.add_paragraph()  # espace


def _add_metadata_table(doc: Document, metadata: dict):
    """Tableau des métadonnées de l'audit."""
    rows_data = [
        ('Client', metadata.get('client', '')),
        ('Site / adresse', metadata.get('site', '')),
        ('Date de l\'audit', metadata.get('date', '')),
        ('Mandat / réf.', metadata.get('mandat', '')),
        ('Auditeur', metadata.get('auditeur', '')),
        ('Outils', 'Audit de sécurité Wi-Fi, wlanpi'),
    ]

    table = doc.add_table(rows=len(rows_data), cols=2)
    _set_table_style(table)
    table.alignment = WD_TABLE_ALIGNMENT.LEFT

    for i, (label, value) in enumerate(rows_data):
        row = table.rows[i]
        # Cellule label
        lc = row.cells[0]
        lc.width = Cm(4.5)
        _set_cell_bg(lc, META_HEADER_BG)
        lp = lc.paragraphs[0]
        lp.paragraph_format.space_before = Pt(3)
        lp.paragraph_format.space_after = Pt(3)
        lr = lp.add_run(label)
        lr.bold = True
        lr.font.size = Pt(9)
        lr.font.color.rgb = HEADER_TEXT

        # Cellule valeur
        vc = row.cells[1]
        vc.width = Cm(11.5)
        _set_cell_bg(vc, VERY_LIGHT_GRAY)
        vp = vc.paragraphs[0]
        vp.paragraph_format.space_before = Pt(3)
        vp.paragraph_format.space_after = Pt(3)
        vr = vp.add_run(str(value))
        vr.font.size = Pt(9)

    doc.add_paragraph()


def _add_executive_summary(doc: Document, networks: list[dict], metadata: dict):
    """Génère le sommaire exécutif automatiquement."""
    total = len(networks)
    critical_count = sum(1 for n in networks if n.get('risk') in ('CRITIQUE', 'ÉLEVÉ'))
    open_wep = sum(1 for n in networks if n.get('auth') in ('Open', 'WEP'))
    tkip_count = sum(1 for n in networks if n.get('cipher') == 'TKIP' or n.get('auth') == 'WPA1-Personal')
    wpa3_count = sum(1 for n in networks if n.get('risk') == 'EXCELLENT')
    wps_count = sum(1 for n in networks if n.get('wps_warning'))

    summary = (
        f"L'audit passif a relevé {total} réseau{'x' if total > 1 else ''} Wi-Fi dans le périmètre "
        f"défini. {critical_count} présente{'nt' if critical_count > 1 else ''} un chiffrement absent ou "
        f"obsolète (ouvert/WEP/TKIP) \u2014 correction immédiate requise."
    )

    if open_wep > 0:
        summary += (
            f" {open_wep} réseau{'x' if open_wep > 1 else ''} sans chiffrement ou avec WEP "
            f"expose{'nt' if open_wep > 1 else ''} les utilisateurs à l'interception totale du trafic."
        )

    if tkip_count > 0:
        summary += (
            f" {tkip_count} réseau{'x' if tkip_count > 1 else ''} utilisent TKIP ou WPA1, "
            f"protocoles officiellement retirés par la Wi-Fi Alliance."
        )

    if wpa3_count > 0:
        summary += (
            f" {wpa3_count} réseau{'x' if wpa3_count > 1 else ''} atteignent le niveau EXCELLENT "
            f"avec WPA3 \u2014 \u00e0 prendre comme r\u00e9f\u00e9rence pour la migration."
        )

    if wps_count > 0:
        summary += (
            f" {wps_count} point{'s' if wps_count > 1 else ''} d'acc\u00e8s "
            f"ont WPS actif, exposant un vecteur d'attaque suppl\u00e9mentaire (Pixie Dust)."
        )

    _add_body(doc, summary, size_pt=10)

    # Tableau récapitulatif rapide
    risk_counts = Counter(n.get('risk', 'MOYEN') for n in networks)
    if risk_counts:
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(6)
        p.paragraph_format.space_after = Pt(2)
        r = p.add_run('Répartition rapide par niveau de risque :')
        r.bold = True
        r.font.size = Pt(10)

        summary_parts = []
        for lvl in RISK_ORDER:
            count = risk_counts.get(lvl, 0)
            if count > 0:
                summary_parts.append(f'{lvl}: {count}')
        _add_body(doc, ' | '.join(summary_parts), size_pt=10)


def _add_scope_section(doc: Document, metadata: dict):
    """Section portée et méthode."""
    site = metadata.get('site', '[site]')
    iface = metadata.get('iface', 'wlan1')
    duration = metadata.get('duration_min', 60)

    text = (
        f"L'audit a été conduit en mode passif (écoute sans association) sur le périmètre "
        f"«\u202f{site}\u202f». Aucun paquet n'a été injecté sur le réseau : l'activité est "
        f"transparente et sans impact sur les services en production.\n\n"
        f"Méthode : capture et analyse des trames Beacon et Probe Response via WLANPi "
        f"(interface {iface}), pendant une durée approximative de {duration}\u202fminutes. "
        f"Les informations collectées se limitent aux données diffusées publiquement par chaque "
        f"point d'accès dans ses trames de gestion 802.11 : SSID, BSSID, canal, fréquence, "
        f"RSN/WPA IE (capacités de chiffrement et d'authentification), et niveau de signal (RSSI).\n\n"
        f"La présence d'un réseau dans ce rapport ne signifie pas qu'il appartient au client — "
        f"des réseaux de voisinage peuvent figurer si leur signal est capté depuis le périmètre audité."
    )
    _add_body(doc, text, size_pt=10)


def _add_summary_table(doc: Document, networks: list[dict]):
    """Section 3 : tableau de synthèse des niveaux."""
    risk_counts = Counter(n.get('risk', 'MOYEN') for n in networks)

    headers = ['NIVEAU', 'NOMBRE', 'SIGNIFICATION']
    table = doc.add_table(rows=1 + len(RISK_ORDER), cols=3)
    _set_table_style(table)
    table.alignment = WD_TABLE_ALIGNMENT.LEFT

    # En-tête
    hrow = table.rows[0]
    widths = [Cm(3.0), Cm(2.0), Cm(11.0)]
    for i, (hdr, w) in enumerate(zip(headers, widths)):
        cell = hrow.cells[i]
        cell.width = w
        _set_cell_bg(cell, HEADER_BG)
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(3)
        p.paragraph_format.space_after = Pt(3)
        r = p.add_run(hdr)
        r.bold = True
        r.font.size = Pt(9)
        r.font.color.rgb = HEADER_TEXT
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER

    # Lignes de données
    for i, level in enumerate(RISK_ORDER):
        count = risk_counts.get(level, 0)
        row = table.rows[i + 1]
        bg = RISK_BG[level]

        # NIVEAU
        c0 = row.cells[0]
        c0.width = Cm(3.0)
        _set_cell_bg(c0, bg)
        p0 = c0.paragraphs[0]
        p0.paragraph_format.space_before = Pt(3)
        p0.paragraph_format.space_after = Pt(3)
        p0.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r0 = p0.add_run(level)
        r0.bold = True
        r0.font.size = Pt(9)
        r0.font.color.rgb = HEADER_TEXT

        # NOMBRE
        c1 = row.cells[1]
        c1.width = Cm(2.0)
        _set_cell_bg(c1, VERY_LIGHT_GRAY if count == 0 else bg)
        p1 = c1.paragraphs[0]
        p1.paragraph_format.space_before = Pt(3)
        p1.paragraph_format.space_after = Pt(3)
        p1.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r1 = p1.add_run(str(count))
        r1.bold = True
        r1.font.size = Pt(10)
        r1.font.color.rgb = HEADER_TEXT if count > 0 else RGBColor(0x44, 0x44, 0x44)

        # SIGNIFICATION
        c2 = row.cells[2]
        c2.width = Cm(11.0)
        bg_sig = VERY_LIGHT_GRAY if count == 0 else 'FFF9F0' if level == 'ÉLEVÉ' else VERY_LIGHT_GRAY
        _set_cell_bg(c2, VERY_LIGHT_GRAY)
        p2 = c2.paragraphs[0]
        p2.paragraph_format.space_before = Pt(3)
        p2.paragraph_format.space_after = Pt(3)
        r2 = p2.add_run(RISK_SIGNIFICATION[level])
        r2.font.size = Pt(9)
        if count == 0:
            r2.font.color.rgb = RGBColor(0x99, 0x99, 0x99)

    doc.add_paragraph()


def _add_networks_table(doc: Document, networks: list[dict]):
    """Section 4 : tableau détaillé des réseaux, trié par risque."""
    sorted_nets = sorted(networks, key=lambda n: RISK_ORDER.index(n.get('risk', 'MOYEN')))

    headers = ['RISQUE', 'SSID', 'SÉCURITÉ', 'CAN.', 'BANDE', 'RSSI', 'CONSTAT']
    col_widths = [Cm(2.2), Cm(3.0), Cm(2.8), Cm(1.0), Cm(1.6), Cm(1.2), Cm(5.2)]

    table = doc.add_table(rows=1 + len(sorted_nets), cols=7)
    _set_table_style(table)
    table.alignment = WD_TABLE_ALIGNMENT.LEFT

    # En-tête
    hrow = table.rows[0]
    for i, (hdr, w) in enumerate(zip(headers, col_widths)):
        cell = hrow.cells[i]
        cell.width = w
        _set_cell_bg(cell, HEADER_BG)
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(2)
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(hdr)
        r.bold = True
        r.font.size = Pt(8)
        r.font.color.rgb = HEADER_TEXT

    # Lignes de données
    for i, ap in enumerate(sorted_nets):
        risk = ap.get('risk', 'MOYEN')
        row = table.rows[i + 1]
        bg = RISK_BG.get(risk, '888888')
        row_bg = VERY_LIGHT_GRAY if i % 2 == 0 else 'EAECEE'

        ssid = ap.get('ssid', '') or '[hidden]'
        auth = ap.get('auth', '')
        cipher = ap.get('cipher', '')
        pmf = ap.get('pmf', 'Disabled')
        wps = ap.get('wps', False)
        chan = str(ap.get('channel', ''))
        band = ap.get('band', '')
        rssi = str(ap.get('rssi', ''))
        constat = ap.get('constat', '')

        security_str = auth
        if cipher and cipher != 'None':
            security_str += f' / {cipher}'
        if wps:
            security_str += ' [WPS]'

        values = [risk, ssid, security_str, chan, band, f'{rssi} dBm', constat]

        for j, (val, w) in enumerate(zip(values, col_widths)):
            cell = row.cells[j]
            cell.width = w
            if j == 0:
                _set_cell_bg(cell, bg)
            else:
                _set_cell_bg(cell, row_bg)
            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.space_after = Pt(2)
            if j == 6:  # constat : plus petit
                p.alignment = WD_ALIGN_PARAGRAPH.LEFT
            else:
                p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            r = p.add_run(val)
            r.font.size = Pt(8) if j != 6 else Pt(7)
            if j == 0:
                r.bold = True
                r.font.color.rgb = HEADER_TEXT

    doc.add_paragraph()


def _add_recommendations(doc: Document, networks: list[dict]):
    """Section 5 : recommandations générées dynamiquement selon les niveaux présents."""
    risks_present = set(n.get('risk', '') for n in networks)
    any_wps = any(n.get('wps_warning') for n in networks)
    has_open_wep = any(n.get('auth') in ('Open', 'WEP') for n in networks)
    has_wpa1_tkip = any(n.get('auth') == 'WPA1-Personal' or n.get('cipher') == 'TKIP' for n in networks)
    has_wpa2_personal = any(n.get('auth') == 'WPA2-Personal' for n in networks)
    has_enterprise = any(n.get('auth') in ('WPA2-Enterprise', 'WPA3-Enterprise') for n in networks)

    recos = []

    if 'CRITIQUE' in risks_present:
        recos.append((
            'R1 — Élimination immédiate des réseaux ouverts et WEP',
            [
                'Désactiver ou sécuriser immédiatement tout réseau en mode Open ou WEP.',
                'Si un réseau ouvert est intentionnel (portail captif), migrer vers OWE '
                '(Opportunistic Wireless Encryption, WPA3) pour chiffrer le trafic sans '
                'nécessiter de mot de passe.',
                'WEP est cassé cryptographiquement depuis 2001 — aucun niveau de clé ne '
                'le rend sûr. Migration vers WPA3-SAE obligatoire.',
                'Délai cible : immédiat (0-5 jours ouvrables).',
            ]
        ))

    if 'ÉLEVÉ' in risks_present:
        recos.append((
            'R2 — Migration hors WPA1 / TKIP',
            [
                'Désactiver WPA1 et TKIP sur tous les points d\'accès.',
                'Configurer le chiffrement en WPA2 ou WPA3 avec CCMP (AES) uniquement.',
                'Sur les AP Cisco/Meraki/Aruba/Ubiquiti, désactiver explicitement '
                'le mode WPA1/TKIP dans les profils SSID.',
                'Tester la compatibilité des clients avant déploiement (les appareils '
                'IoT anciens peuvent ne pas supporter CCMP — à remplacer si nécessaire).',
                'Délai cible : 2-4 semaines.',
            ]
        ))

    if 'MOYEN' in risks_present:
        recos.append((
            'R3 — Migration WPA2-Personnel vers WPA3-SAE',
            [
                'Planifier la migration de WPA2-Personnel vers WPA3-SAE sur tous les SSID '
                'concernés, en commençant par les SSID internes.',
                'Activer le mode de transition WPA2/WPA3 si des clients legacy doivent '
                'coexister temporairement.',
                'Utiliser une phrase de passe longue (≥ 20 caractères, aléatoire) en '
                'attendant la migration complète.',
                'WPA3-SAE élimine les attaques par dictionnaire hors-ligne grâce à SAE '
                '(Simultaneous Authentication of Equals).',
                'Délai cible : 3-6 mois selon le parc client.',
            ]
        ))

    if 'BON' in risks_present:
        recos.append((
            'R4 — Renforcement WPA2-Entreprise et activation de PMF',
            [
                'Vérifier que le certificat serveur RADIUS est valide et qu\'il est validé '
                'par les supplicants (éviter la confiance aveugle).',
                'Activer PMF (Protected Management Frames) en mode Required sur tous les '
                'SSID d\'entreprise — protège contre les attaques de déauthentification.',
                'Envisager la migration vers WPA3-Enterprise pour les SSID les plus sensibles.',
                'Documenter et auditer régulièrement les identités dans le serveur RADIUS.',
                'Délai cible : 1-3 mois.',
            ]
        ))

    if any_wps:
        recos.append((
            'R5 — Désactivation de WPS sur tous les points d\'accès',
            [
                'Désactiver WPS (Wi-Fi Protected Setup) sur l\'ensemble des AP — même sur '
                'les réseaux WPA3.',
                'WPS PIN est vulnérable à l\'attaque Pixie Dust (récupération de la clé '
                'réseau en quelques secondes) et au brute-force du PIN 8 chiffres.',
                'La commodité offerte par WPS ne justifie plus le risque depuis la '
                'découverte des vulnérabilités en 2011.',
                'Vérifier que la désactivation est persistante après redémarrage de l\'AP.',
            ]
        ))

    recos.append((
        'R6 — Audit actif et test de pénétration',
        [
            'Compléter cet audit passif par un audit actif (association, capture de handshake, '
            'test de segmentation VLAN) pour valider la posture réelle.',
            'Effectuer un test de pénétration Wi-Fi annuel par un testeur certifié.',
            'Mettre en place un système WIDS/WIPS (Wireless Intrusion Detection/Prevention) '
            'pour détecter les AP non autorisés et les attaques en temps réel.',
        ]
    ))

    for title, bullets in recos:
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(8)
        p.paragraph_format.space_after = Pt(2)
        r = p.add_run(title)
        r.bold = True
        r.font.size = Pt(10)
        r.font.color.rgb = RGBColor(0x2C, 0x3E, 0x50)

        for bullet in bullets:
            bp = doc.add_paragraph(style='List Bullet')
            bp.paragraph_format.space_before = Pt(1)
            bp.paragraph_format.space_after = Pt(1)
            br = bp.add_run(bullet)
            br.font.size = Pt(9)

    doc.add_paragraph()


def _add_limits_section(doc: Document):
    """Section 6 : limites de l'audit passif."""
    text = (
        "L'audit passif présente les limites inhérentes à sa nature non-intrusive :\n\n"
        "• Réseaux cachés (SSID non diffusé) : seuls les AP ayant répondu à des "
        "Probe Request ou diffusé spontanément sont visibles. Un SSID caché n'est pas "
        "une mesure de sécurité efficace, mais il peut ne pas figurer dans ce rapport.\n\n"
        "• Chiffrement WEP : sans capturer une quantité suffisante de trafic (IVs), la "
        "présence de WEP peut ne pas être distinguée d'Open si le flag Privacy n'est "
        "pas détecté dans les Beacon.\n\n"
        "• Segmentation et VLAN : l'audit passif ne peut pas vérifier si les VLAN sont "
        "correctement isolés, si le client peut atteindre des ressources non autorisées, "
        "ou si l'infrastructure cœur est correctement configurée.\n\n"
        "• Clients rogue et AP evil-twin : l'audit passif ne détecte pas les AP malveillants "
        "configurés pour imiter les SSID légitimes si leur BSSID n'est pas connu à l'avance.\n\n"
        "• Couverture RF : la qualité du signal relevé dépend de la position du WLANPi au "
        "moment du scan. Des AP distants ou orientés différemment peuvent être sous-représentés.\n\n"
        "• Portée temporelle : les réseaux présentés correspondent aux AP actifs durant la "
        "fenêtre d'audit. Des SSID temporaires ou schedules peuvent être absents."
    )
    _add_body(doc, text, size_pt=9)


def _add_key_strength_section(doc: Document):
    """Section 7 : force des clés et résistance à l'intrusion."""
    _add_body(doc,
        "Les tableaux suivants indiquent le temps estimé de récupération d'une clé Wi-Fi "
        "selon le protocole et la puissance de calcul disponible (attaque hors-ligne sur "
        "handshake capturé). Ces estimations supposent une attaque par dictionnaire ou "
        "force brute sur GPU consumer (RTX 4090, ~2M PMK/s pour WPA2).",
        size_pt=9)

    doc.add_paragraph()

    # Tableau 1 : résistance par protocole
    _add_heading(doc, 'Résistance par protocole d\'authentification', level=2)
    proto_data = [
        ('Open',              'N/A',             'Nul',         'Aucun chiffrement — trafic en clair.'),
        ('WEP',               '< 2 minutes',     'Nul',         'Attaque statistique sur IVs (aircrack-ng).'),
        ('WPA1-Personnel / TKIP', '< 24 h',      'Faible',      'Attaque dictionnaire sur handshake 4-way.'),
        ('WPA2-Personnel',    '1 h – plusieurs années', 'Moyen', 'Dépend de la longueur/complexité du PSK.'),
        ('WPA2-Entreprise',   'Impraticable',    'Bon',         'Pas de PSK; EAP — attaque sur certificat.'),
        ('WPA3-SAE',          'Impraticable',    'Excellent',   'SAE : pas de handshake captu\u2019rable en mode passif.'),
        ('WPA3-Entreprise',   'Impraticable',    'Excellent',   'PMF obligatoire + Suite-B si configuré.'),
        ('OWE',               'Impraticable',    'Bon',         'Diffie-Hellman par association, pas de PSK.'),
    ]

    headers = ['Protocole', 'Temps de crack (GPU)', 'Niveau', 'Note']
    col_widths = [Cm(3.5), Cm(3.5), Cm(2.0), Cm(7.0)]
    table = doc.add_table(rows=1 + len(proto_data), cols=4)
    _set_table_style(table)

    hrow = table.rows[0]
    for i, (h, w) in enumerate(zip(headers, col_widths)):
        cell = hrow.cells[i]
        cell.width = w
        _set_cell_bg(cell, HEADER_BG)
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(2)
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(h)
        r.bold = True
        r.font.size = Pt(8)
        r.font.color.rgb = HEADER_TEXT

    for i, row_data in enumerate(proto_data):
        row = table.rows[i + 1]
        bg = VERY_LIGHT_GRAY if i % 2 == 0 else 'EAECEE'
        for j, (val, w) in enumerate(zip(row_data, col_widths)):
            cell = row.cells[j]
            cell.width = w
            _set_cell_bg(cell, bg)
            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.space_after = Pt(2)
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER if j < 3 else WD_ALIGN_PARAGRAPH.LEFT
            r = p.add_run(val)
            r.font.size = Pt(8)

    doc.add_paragraph()

    # Tableau 2 : résistance par longueur de PSK
    _add_heading(doc, 'Résistance estimée selon longueur du PSK (WPA2-Personnel)', level=2)
    psk_data = [
        ('8 caractères',  'alphanumérique',  '< 3 jours',       'À proscrire absolument.'),
        ('10 caractères', 'alphanumérique',  '2 mois – 2 ans',  'Insuffisant pour données sensibles.'),
        ('12 caractères', 'complexe',        '10 – 200 ans',    'Minimum recommandé avec WPA2.'),
        ('16 caractères', 'complexe',        'Astronomique',    'Recommandé — migrer vers WPA3 dès possible.'),
        ('20+ caractères','aléatoire',       'Impraticable',    'Idéal en attendant WPA3-SAE.'),
    ]

    headers2 = ['Longueur PSK', 'Complexité', 'Temps de crack estimé', 'Recommandation']
    col_widths2 = [Cm(2.8), Cm(2.8), Cm(3.4), Cm(7.0)]
    table2 = doc.add_table(rows=1 + len(psk_data), cols=4)
    _set_table_style(table2)

    hrow2 = table2.rows[0]
    for i, (h, w) in enumerate(zip(headers2, col_widths2)):
        cell = hrow2.cells[i]
        cell.width = w
        _set_cell_bg(cell, HEADER_BG)
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(2)
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r = p.add_run(h)
        r.bold = True
        r.font.size = Pt(8)
        r.font.color.rgb = HEADER_TEXT

    for i, row_data in enumerate(psk_data):
        row = table2.rows[i + 1]
        bg = VERY_LIGHT_GRAY if i % 2 == 0 else 'EAECEE'
        for j, (val, w) in enumerate(zip(row_data, col_widths2)):
            cell = row.cells[j]
            cell.width = w
            _set_cell_bg(cell, bg)
            p = cell.paragraphs[0]
            p.paragraph_format.space_before = Pt(2)
            p.paragraph_format.space_after = Pt(2)
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER if j < 3 else WD_ALIGN_PARAGRAPH.LEFT
            r = p.add_run(val)
            r.font.size = Pt(8)

    doc.add_paragraph()


def _add_footer(doc: Document):
    """Ajoute un pied de page avec numérotation."""
    for section in doc.sections:
        footer = section.footer
        footer.is_linked_to_previous = False
        p = footer.paragraphs[0] if footer.paragraphs else footer.add_paragraph()
        p.clear()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER

        run1 = p.add_run('R\u00e9seaux Eagle Inc. \u2014 Rapport confidentiel \u00b7 page\u00a0')
        run1.font.size = Pt(8)
        run1.font.color.rgb = RGBColor(0x77, 0x77, 0x77)

        # Champ numéro de page
        fldChar1 = OxmlElement('w:fldChar')
        fldChar1.set(qn('w:fldCharType'), 'begin')
        instrText = OxmlElement('w:instrText')
        instrText.set(qn('xml:space'), 'preserve')
        instrText.text = 'PAGE'
        fldChar2 = OxmlElement('w:fldChar')
        fldChar2.set(qn('w:fldCharType'), 'end')

        run2 = p.add_run()
        run2.font.size = Pt(8)
        run2.font.color.rgb = RGBColor(0x77, 0x77, 0x77)
        run2._r.append(fldChar1)
        run2._r.append(instrText)
        run2._r.append(fldChar2)


def _add_confidentiality_notice(doc: Document):
    """Mention de confidentialité finale."""
    doc.add_paragraph()
    table = doc.add_table(rows=1, cols=1)
    cell = table.rows[0].cells[0]
    _set_cell_bg(cell, HEADER_BG)
    p = cell.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.space_after = Pt(6)
    r = p.add_run(
        'DOCUMENT CONFIDENTIEL — Ce rapport est destiné exclusivement au client mentionné '
        'en page de garde. Toute reproduction ou diffusion sans autorisation écrite de '
        'Réseaux Eagle Inc. est interdite. © Réseaux Eagle Inc. '
        + str(datetime.date.today().year)
    )
    r.font.size = Pt(8)
    r.font.color.rgb = RGBColor(0xBD, 0xC3, 0xC7)
