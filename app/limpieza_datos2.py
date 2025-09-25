import pandas as pd
from datetime import datetime
import psycopg2
import numpy as np

import pandas as pd
from datetime import datetime
import psycopg2
import uuid


def clean_data_ddos(archive_dic):
    df = pd.DataFrame([archive_dic])
    df.columns = df.columns.str.strip()

    df = df[['Destination Port', 'Flow Duration', 'Total Fwd Packets','Total Backward Packets','Flow Bytes/s','Flow Packets/s','Fwd Packet Length Mean','Fwd Packet Length Std','Min Packet Length','Max Packet Length','Flow IAT Mean','Flow IAT Std','SYN Flag Count','ACK Flag Count','Down/Up Ratio','Active Mean','Idle Mean','Label']]
    mapping = {
        "Web Attack ´?¢ Sql Injection": "Critical",
        "Web Attack ´?¢ XSS": "High",
        "Web Attack ´?¢ Brute Force": "Moderate",
        "BENIGN": "Benign"
    }
    df["Score"] = df["Label"].map(mapping)

    mapping2 = {
        "Web Attack ´?¢ Sql Injection": 3,
        "Web Attack ´?¢ XSS": 2,
        "Web Attack ´?¢ Brute Force": 1,
        "BENIGN": 0
    }
    df["Severity"] = df["Label"].map(mapping2)

    mapping3 = {
        "Critical": "Incidencia",
        "Moderate": "Alerta",
        "High": "Alerta",
        "Benign": "Info"
    }

    df["Tipo"] = df["Score"].map(mapping3)
    
    df = df.rename(columns={"Label": "Indicadores"})

    df["Indicadores"] = df["Indicadores"].str.replace("Web Attack ´?¢ ", "", regex=False)
    
    columns = [
    'Destination Port',
    'Estandar',
    'Description',
    'Ataques/CVEs tipicos',
    'Como proteger'
    ]

    datos = [
    [80, 'HTTP',
     'Tráfico web sin TLS. Expuesto a robo/manipulación de datos (MITM) y vulnerabilidades de aplicaciones web (XSS, SQLi, RCE) y del propio servidor.',
     'Fallos en frameworks/servidores web y módulos (p. ej., deserialización, path traversal).',
     'Redirigir 80→443, WAF, cabeceras seguras (HSTS/CSP), hardening del servidor, parches continuos y pruebas SAST/DAST.'],

    [53, 'DNS',
     'Resolución de nombres. Muy usado en ataques de envenenamiento de caché, spoofing, tunneling y amplificación DDoS.',
     'Vulnerabilidades en BIND/Unbound/dnsmasq; abuso de recursión abierta.',
     'Desactivar recursión pública, aplicar rate-limit, DNSSEC, listas de control de acceso, egress filtering para impedir túneles DNS.'],

    [443, 'HTTPS',
     'Web con TLS. Riesgo principal: mala configuración (protocolos/algoritmos débiles, certificados inválidos) además de las mismas vulnerabilidades de la app web que en 80.',
     'Downgrade/MITM si hay TLS obsoleto; fallos en librerías TLS y servidores.',
     'TLS 1.2/1.3, desactivar suites inseguras, HSTS, pinning si aplica, automatizar renovación de certificados, WAF y hardening.'],

    [36788, 'No estándar',
     'Puerto efímero no asociado a un servicio conocido.',
     'Uso por backdoors/C2 o exfiltración.',
     'Política de mínimo privilegio en firewall, bloquear si no se usa, monitorizar flujos inusuales y aplicar alertas SIEM.'],

    [4537, 'No estándar',
     'Puerto sin asignación común.',
     'Canales ocultos de malware, P2P o túneles.',
     'Egress filtering estricto, IDS/IPS, cerrar servicios no documentados y revisar binarios/servicios.'],

    [39717, 'No estándar',
     'Puerto efímero con tráfico alto no habitual.',
     'Escaneo, exfiltración o C2.',
     'Bloquear por defecto, permitir solo listas blancas, correlacionar con reputación IP y detectar patrones anómalos.'],

    [49836, 'No estándar',
     'Puerto efímero sin servicio documentado.',
     'Uso oportunista por malware/troyanos.',
     'Segmentación de red, EDR en endpoints, alertas por conexiones salientes persistentes.'],

    [51908, 'No estándar',
     'Puerto sin servicio conocido.',
     'Comunicaciones P2P o botnets.',
     'Bloqueo si no está en catálogo, inspección profunda (DPI) y reglas de detección de beaconing.'],

    [49256, 'No estándar',
     'Actividad inusual si actúa como servidor.',
     'Escaneo y canales de mando y control.',
     'Registrar y alertar scans, limitar exposición, revisar procesos que hacen bind a este puerto.'],

    [54426, 'No estándar',
     'Puerto efímero similar a otros altos.',
     'RATs y túneles de datos.',
     'Bloquear por defecto, listas blancas, correlación con destinos/horarios y revisión de integridad del host.']
    ]

    df2 = pd.DataFrame(datos, columns=columns)

    df["Destination Port"] = df["Destination Port"].astype(int)
    df2["Destination Port"] = df2["Destination Port"].astype(int)

    df = pd.merge(df, df2, on="Destination Port", how="left")


    df["ddos_id"] = [(uuid.uuid4().int) %1_000_000]
    

    now = datetime.now()
    df["Date"] = now.date()
    df["Time"] = now.strftime("%H:%M:%S")

    
        
    conn = psycopg2.connect(
    dbname="desafiogrupo1",
    user="desafiogrupo1_user",
    password="g7jS0htW8QqiGPRymmJw0IJgb04QO3Jy",
    host="dpg-d36i177fte5s73bgaisg-a.oregon-postgres.render.com",
    port="5432"
    )

    


    cur = conn.cursor()
    records = [
        {
            "id": row['ddos_id'],
            "company_id": 1,
            "type": row["Tipo"],
            "indicators": row["Indicadores"],
            "severity": row["Severity"],
            "date": row["Date"],
            "time": row["Time"],
            "actions_taken": 1
        }   
        for _, row in df.iterrows()
    ]
    

    cur.executemany("""
        INSERT INTO logs (id, company_id, type, indicators, severity, date, time,actions_taken)
        VALUES (%(id)s, %(company_id)s, %(type)s, %(indicators)s, %(severity)s, %(date)s, %(time)s, %(actions_taken)s)
        """, records)



    
    records_2 = [
            {
            'log_id':  row['ddos_id'],
            'Destination Port': row['Destination Port'],
            'Flow Duration': row['Flow Duration'], 
            'Total Fwd Packets': row['Total Fwd Packets'],
            'Total Backward Packets': row['Total Backward Packets'],
            'Flow Bytes/s':row['Flow Bytes/s'] ,
            'Flow Packets/s': row['Flow Packets/s'],
            'Fwd Packet Length Mean': row['Fwd Packet Length Mean'],
            'Fwd Packet Length Std': row['Fwd Packet Length Std'],
            'Min Packet Length':row['Min Packet Length'],
            'Max Packet Length': row['Max Packet Length'],
            'Flow IAT Mean':row['Flow IAT Mean'] ,
            'Flow IAT Std': row['Flow IAT Std'],
            'SYN Flag Count': row['SYN Flag Count'],
            'ACK Flag Count':row['ACK Flag Count'] ,
            'Down/Up Ratio': row['Down/Up Ratio'],
            'Active Mean':row['Active Mean'] ,
            'Idle Mean': row['Idle Mean'],
            'Score':row['Score'],
            'Severity': row['Severity'],
            'Tipo': row['Tipo'],
            'Indicadores': row['Indicadores'],
            'Estandar':row['Estandar'] ,
            'Description': row['Description'],
            'Ataques/CVEs tipicos': row['Ataques/CVEs tipicos'],
            'Como proteger': row['Como proteger'],
            'date': row['Date'],
            'time': row['Time']

        }
            for _, row in df.iterrows()
        ]

    cur.executemany("""
        INSERT INTO ddos (
            "log_id", "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Flow Bytes/s", "Flow Packets/s", "Fwd Packet Length Mean", "Fwd Packet Length Std",
            "Min Packet Length", "Max Packet Length", "Flow IAT Mean", "Flow IAT Std",
            "SYN Flag Count", "ACK Flag Count", "Down/Up Ratio", "Active Mean", "Idle Mean",
            "Indicadores", "Score", "Severity", "Tipo", "Estandar", "Description",
            "Ataques/CVEs tipicos", "Como proteger", "date", "time"
        )
        VALUES (
            %(log_id)s, %(Destination Port)s, %(Flow Duration)s, %(Total Fwd Packets)s, %(Total Backward Packets)s,
            %(Flow Bytes/s)s, %(Flow Packets/s)s, %(Fwd Packet Length Mean)s, %(Fwd Packet Length Std)s,
            %(Min Packet Length)s, %(Max Packet Length)s, %(Flow IAT Mean)s, %(Flow IAT Std)s,
            %(SYN Flag Count)s, %(ACK Flag Count)s, %(Down/Up Ratio)s, %(Active Mean)s, %(Idle Mean)s,
            %(Indicadores)s, %(Score)s, %(Severity)s, %(Tipo)s, %(Estandar)s, %(Description)s,
            %(Ataques/CVEs tipicos)s, %(Como proteger)s, %(date)s, %(time)s
        )
    """, records_2)


    conn.commit()
    cur.close()
    conn.close()




# ================  PHISHING  ====================
import pandas as pd
import numpy as np
import psycopg2
import psycopg2.extras
from datetime import datetime
import matplotlib.pyplot as plt
import requests
import base64
import time
from collections import OrderedDict
from dotenv import load_dotenv
import os
import uuid

load_dotenv()
VT_BASE = "https://www.virustotal.com/api/v3"
API_KEY = "d76bc448e37843d6ee81f283d1cf2ee5df8a66df211bd07797bfc31b68576f1b"
if not API_KEY:
    raise RuntimeError("VT_API_KEY no definida. Exporta tu API key en la variable de entorno VT_API_KEY.")

HEADERS = {"accept": "application/json", "x-apikey": API_KEY}

URL_KEYS_ORDER = ["url", "last_analysis_stats", "status", "network_location"]
NETWORK_LOCATION_KEYS_ORDER = [
    "whois", "tags", "last_dns_records", "popularity_ranks", "last_analysis_date",
    "last_https_certificate", "last_analysis_stats", "last_dns_records_date",
    "last_modification_date", "registrar", "reputation", "expiration_date",
    "tld", "last_https_certificate_date", "jarm", "categories"
]

NETLOC_FIELDS_DEFAULTS = {
    "whois": "",
    "tags": [],
    "last_dns_records": [],
    "popularity_ranks": {},
    "last_https_certificate": {},
    "last_analysis_stats": {},
    "categories": {}
}

def clean_data_phishing(dict):
    df = pd.DataFrame([dict])
    df['HasPopup'] = (df['NoOfPopup'] >= 1).astype(int)
    df["Nivel3_Alta"] = ((df["IsDomainIP"] == 1) |((df["HasPasswordField"] == 1) & (df["IsHTTPS"] == 0)) |(df["HasExternalFormSubmit"] == 1)).astype(int)
    df["Nivel2_Media"] = ((df["ObfuscationRatio"] > 0.2) |(df["DomainLength"] > 25) |(df["NoOfSubDomain"] > 3)).astype(int)
    df["Nivel1_Baja"] = ((df["DomainTitleMatchScore"] < 1.0) |(df["TLDLegitimateProb"] < 0.25) |(df["NoOfPopup"] > 0)).astype(int)
    df['IsPhishing'] = ((df['Nivel3_Alta'] == 1) | (df['Nivel2_Media'] == 1) | (df['Nivel1_Baja'] == 1)).astype(int)

    conditions = [(df["IsPhishing"] == 0),(df["Nivel3_Alta"] == 1),(df["Nivel2_Media"] == 1) | (df["Nivel1_Baja"] == 1) ]
    choices = ["Info", "Incidencia", "Alerta"]
    df["type"] = np.select(conditions, choices, default="Info")
    df["indicators"] = df["IsPhishing"].map({1: "Posible phishing", 0: "Correo seguro"})
    df["severity"] = df["IsPhishing"]
    now = datetime.now()
    df['date'] = now.date()
    df['time'] = now.strftime("%H:%M:%S")

    logs_id = (uuid.uuid4().int) %1_000_000
    df["id"] = logs_id

    conn = psycopg2.connect(
        dbname="desafiogrupo1",
        user="desafiogrupo1_user",
        password="g7jS0htW8QqiGPRymmJw0IJgb04QO3Jy",
        host="dpg-d36i177fte5s73bgaisg-a.oregon-postgres.render.com",
        port="5432"
    )
    
    cur = conn.cursor()
    records = [
        {
            "id": row['id'],
            "company_id": 1,
            "type": row['type'],
            "indicators": row['indicators'],
            "severity": row['severity'],
            "date": row['date'],
            "time": row['time'],
            "actions_taken": 1
        }
        for _, row in df.iterrows()
    ]

    cur.executemany("""
        INSERT INTO logs (id, company_id, type, indicators, severity, date, time, actions_taken)
        VALUES (%(id)s, %(company_id)s, %(type)s, %(indicators)s, %(severity)s, %(date)s, %(time)s, %(actions_taken)s)
    """, records)
    conn.commit()
    cur.close()
    conn.close()

    insertar_phishing_enriquecido(df['URL'].iloc[0], logs_id)

# -----------------------------
# Funciones auxiliares
def _remove_key_recursive(obj, key_to_remove="last_analysis_results"):
    if isinstance(obj, dict):
        if key_to_remove in obj:
            obj.pop(key_to_remove)
        for v in obj.values():
            _remove_key_recursive(v, key_to_remove)
    elif isinstance(obj, list):
        for item in obj:
            _remove_key_recursive(item, key_to_remove)

def _ordered_network_location(netloc_attrs):
    netloc_out = OrderedDict()
    for k in NETWORK_LOCATION_KEYS_ORDER:
        netloc_out[k] = netloc_attrs.get(k, NETLOC_FIELDS_DEFAULTS.get(k))
    _remove_key_recursive(netloc_out, "last_analysis_results")
    return netloc_out

def _ordered_url_object(url_result):
    od = OrderedDict()
    for k in URL_KEYS_ORDER:
        if k == "network_location" and url_result.get("network_location"):
            od[k] = _ordered_network_location(url_result["network_location"])
        else:
            od[k] = url_result.get(k)
    return od

def safe_get(d, path, default=None):
    keys = path.split(".")
    for key in keys:
        if isinstance(d, dict) and key in d:
            d = d[key]
        else:
            return default
    return d
    
# -----------------------------
# Función principal para consultar VT
def get_url_info(url, retries=2, timeout=10, pause_between_calls=1.0):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    result = {"url": url}

    # 1) /urls/{url_id}
    for attempt in range(retries+1):
        try:
            resp = requests.get(f"{VT_BASE}/urls/{url_id}", headers=HEADERS, timeout=timeout)
            if resp.status_code == 404:
                result["status"] = "URL NO REPORTADA"
                return _ordered_url_object(result)
            if resp.status_code == 401:
                result["status"] = "ERROR_AUTH"
                result["error"] = "401 Unauthorized - revisa tu API key."
                return _ordered_url_object(result)
            resp.raise_for_status()
            attrs = resp.json().get("data", {}).get("attributes", {}) or {}
            result["last_analysis_stats"] = attrs.get("last_analysis_stats", {
                "malicious": 0, "suspicious": 0, "undetected": 0, "harmless": 0, "timeout": 0
            })
            result["status"] = "OK"
            break
        except requests.exceptions.RequestException as e:
            if attempt < retries:
                time.sleep(5)
            else:
                result["status"] = "ERROR"
                result["error_url_object"] = str(e)
                return _ordered_url_object(result)

    time.sleep(pause_between_calls)

    # 2) network_location
    try:
        netloc_resp = requests.get(f"{VT_BASE}/urls/{url_id}/network_location", headers=HEADERS, timeout=timeout)
        if netloc_resp.status_code == 404:
            return _ordered_url_object(result)
        netloc_resp.raise_for_status()
        netloc_data_ref = netloc_resp.json().get("data", {}) or {}
        # attributes embebidos
        netloc_attrs = netloc_data_ref.get("attributes", {}) or {}
        result["network_location"] = netloc_attrs
    except requests.exceptions.RequestException as e:
        result["network_location"] = {}
        result["_error_network_location"] = str(e)

    return _ordered_url_object(result)
def enriquecimiento_phishing(url):
    resultados = []

    r = get_url_info(url, retries=2, timeout=15, pause_between_calls=1.0)
    resultados.append(r)
    time.sleep(2)
    return resultados
# -----------------------------
# Directamente usar esta
def tablas_enriquecimiento_phishing(url):
    filas = []
    for r in enriquecimiento_phishing(url):
        fila = {
            "URL": r.get("url"),
            "status": r.get("status"),
            "malicious": safe_get(r, "last_analysis_stats.malicious"),
            "suspicious": safe_get(r, "last_analysis_stats.suspicious"),
            "undetected": safe_get(r, "last_analysis_stats.undetected"),
            "harmless": safe_get(r, "last_analysis_stats.harmless"),
            "timeout": safe_get(r, "last_analysis_stats.timeout"),
            "whois": safe_get(r, "network_location.whois"),
            "tags": safe_get(r, "network_location.tags"),
            "dns_records": [rec.get("value") for rec in safe_get(r, "network_location.last_dns_records", []) if "value" in rec],
            "last_dns_records_date": safe_get(r, "network_location.last_dns_records_date"),
            "registrar": safe_get(r, "network_location.registrar"),
            "expiration_date": safe_get(r, "network_location.expiration_date"),
            "tld": safe_get(r, "network_location.tld"),
            "issuer": safe_get(r, "network_location.last_https_certificate.issuer"),
            "subject_CN": safe_get(r, "network_location.last_https_certificate.subject.CN"),
            "cert_not_before": safe_get(r, "network_location.last_https_certificate.validity.not_before"),
            "cert_not_after": safe_get(r, "network_location.last_https_certificate.validity.not_after"),
            "cert_key_size": safe_get(r, "network_location.last_https_certificate.public_key.key_size"),
            "thumbprint_sha256": safe_get(r, "network_location.last_https_certificate.thumbprint_sha256"),
            "reputation": safe_get(r, "network_location.reputation"),
            "popularity_ranks": safe_get(r, "network_location.popularity_ranks"),
            "jarm": safe_get(r, "network_location.jarm"),
            "categories": safe_get(r, "network_location.categories"),
        }
        filas.append(fila)
    return pd.DataFrame(filas)
# df_enriquecimiento = tablas_enriquecimiento_phishing(df['URL'].iloc[0]) *******    df['URL'].iloc[0]         O        la url           ********
def insertar_phishing_enriquecido(url, logs_id):
    df = tablas_enriquecimiento_phishing(url)
    df['logs_id'] = logs_id

    conn = psycopg2.connect(
        dbname="desafiogrupo1",
        user="desafiogrupo1_user",
        password="g7jS0htW8QqiGPRymmJw0IJgb04QO3Jy",
        host="dpg-d36i177fte5s73bgaisg-a.oregon-postgres.render.com",
        port="5432"
    )
    
    cur = conn.cursor()
    records = [
        {
            "logs_id": row['logs_id'],
            "url": row['URL'],
            "status": row['status'],
            "malicious": row['malicious'],
            "suspicious": row['suspicious'],
            "undetected": row['undetected'],
            "harmless": row['harmless'],
            "timeout": row['timeout'],
            "whois": row['whois'],
            "tags": row['tags'],
            "dns_records": row['dns_records'],
            "last_dns_records_date": row['last_dns_records_date'],
            "registrar": row['registrar'],
            "expiration_date": row['expiration_date'],
            "tld": row['tld'],
            "issuer": row['issuer'],
            "subject_CN": row['subject_CN'],
            "cert_not_before": row['cert_not_before'],
            "cert_not_after": row['cert_not_after'],
            "cert_key_size": row['cert_key_size'],
            "thumbprint_sha256": row['thumbprint_sha256'],
            "reputation": row['reputation'],
            "popularity_ranks": row['popularity_ranks'],
            "jarm": row['jarm'],
            "categories": row['categories']
        }
        for _, row in df.iterrows()
    ]

    for rec in records:
        for k, v in list(rec.items()):
            if isinstance(v, (dict, list)):
                rec[k] = psycopg2.extras.Json(v)
            # opcional mínimo y seguro: convertir pd.Timestamp a datetime
            # (si no usas pandas.Timestamp en esos campos, no cambia nada)
            elif hasattr(v, "to_pydatetime"):
                try:
                    rec[k] = v.to_pydatetime()
                except Exception:
                    pass

    cur.executemany("""
        INSERT INTO phishing (logs_id, url, status, malicious, suspicious, undetected, harmless, timeout, whois, tags, dns_records,
                    last_dns_records_date, registrar, expiration_date, tld, issuer, subject_CN, cert_not_before, cert_not_after,
                    cert_key_size, thumbprint_sha256, reputation, popularity_ranks, jarm, categories)
        VALUES (%(logs_id)s, %(url)s, %(status)s, %(malicious)s, %(suspicious)s, %(undetected)s, %(harmless)s, %(timeout)s, %(whois)s, %(tags)s, %(dns_records)s,
                    %(last_dns_records_date)s, %(registrar)s, %(expiration_date)s, %(tld)s, %(issuer)s, %(subject_CN)s, %(cert_not_before)s, %(cert_not_after)s,
                    %(cert_key_size)s, %(thumbprint_sha256)s, %(reputation)s, %(popularity_ranks)s, %(jarm)s, %(categories)s)
    """, records)
    conn.commit()
    cur.close()
    conn.close()


# ================  LOGIN  ====================
import pandas as pd
import numpy as np
import psycopg2
from datetime import datetime
import requests
import time
from dotenv import load_dotenv
import os
load_dotenv()
API_KEY = "bc75c37a0bd14e9bfcb283cfa464e290d125218acc693b1193c6754220a38fb74403006313b80bd7"
CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
HEADERS = {"Accept": "application/json", "Key": API_KEY}
DB_CONF = {
    "dbname": "desafiogrupo1",
    "user": "desafiogrupo1_user",
    "password": "g7jS0htW8QqiGPRymmJw0IJgb04QO3Jy",
    "host": "dpg-d36i177fte5s73bgaisg-a.oregon-postgres.render.com",
    "port": "5432"
}
# ----------------- 1) Limpieza -----------------
def clean_data_login2(archive_dic):
    df = pd.DataFrame([archive_dic])
    df.columns = df.columns.str.strip()
    ts = pd.to_datetime(df.get("Login Timestamp"), errors="coerce", utc=True)
    ts = ts.apply(lambda x: x.replace(year=2025) if pd.notna(x) else x)
    df["Date"] = ts.dt.date
    df["Time"] = ts.dt.strftime("%H:%M:%S")
    ls = df.get("Login Successful", pd.Series([False])).fillna(False).astype(bool)
    ia = df.get("Is Attack IP", pd.Series([False])).fillna(False).astype(bool)
    iat = df.get("Is Account Takeover", pd.Series([False])).fillna(False).astype(bool)
    rojo = (ls) & (ia) & (iat)
    naranja = (ls) & (ia) & (~iat)
    amarillo = (~ls) & (ia) & (~iat)
    blanco = (ls) & (~ia) & (~iat)
    df["Severity"] = np.select([rojo, naranja, amarillo, blanco], [3, 2, 1, 0], default=1).astype(int)
    df["Tipo"] = np.select(
        [df["Severity"].eq(3), df["Severity"].isin([1,2]), df["Severity"].eq(0)],
        ["Incidencia", "Alerta", "Info"], default="Info"
    )
    df["Indicadores"] = np.select(
        [df["Severity"].eq(3), df["Severity"].eq(2), df["Severity"].eq(1), df["Severity"].eq(0)],
        ["Robo de credenciales", "Cuenta comprometida", "Ataque fallido", "Login válido"], default=""
    )
    return df
# ----------------- 2) Enriquecimiento -----------------
def check_ip_info(ip, pause=0.5):
    try:
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}
        r = requests.get(CHECK_URL, headers=HEADERS, params=params)
        r.raise_for_status()
        data = r.json().get("data", {})
        info = {
            "ipAddress": data.get("ipAddress"),
            "countryCode": data.get("countryCode"),
            "abuseConfidenceScore": data.get("abuseConfidenceScore"),
            "lastReportedAt": data.get("lastReportedAt"),
            "usageType": data.get("usageType"),
            "domain": data.get("domain"),
            "totalReports": data.get("totalReports")
        }
        time.sleep(pause)
        return info
    except Exception as e:
        print(f"Error con {ip}: {e}")
        return {}
def enrich_login_record(record_dict):
    df_enriq = pd.DataFrame([record_dict])
    ip = check_ip_info(df_enriq.iloc[0]["IP Address"])
    if ip:
        api_info = check_ip_info(ip["ipAddress"])
        for k,v in api_info.items():
            if k != "ipAddress":
                df_enriq[k] = v
    return df_enriq
# ----------------- 3) Inserción con prints de debug -----------------
def insert_into_db_debug(df_clean, df_enriq):
    try:
        print("Conectando a PostgreSQL...")
        conn = psycopg2.connect(**DB_CONF)
        cur = conn.cursor()
        print("Conexión establecida.")
        # Insertar en logs
        row = df_clean.iloc[0]
        record_logs = {
            "company_id": 1,
            "type": row["Tipo"],
            "indicators": row["Indicadores"],
            "severity": int(row["Severity"]),
            "date": row["Date"],
            "time": row["Time"],
            "actions_taken": 1
        }
        print("Datos a insertar en logs:", record_logs)
        insert_logs = """
        INSERT INTO logs (company_id, type, indicators, severity, date, time, actions_taken)
        VALUES (%(company_id)s, %(type)s, %(indicators)s, %(severity)s, %(date)s, %(time)s, %(actions_taken)s)
        RETURNING id;
        """
        cur.execute(insert_logs, record_logs)
        log_id = cur.fetchone()[0]
        print("ID generado en logs:", log_id)
        # Insertar en login
        row_enr = df_enriq.iloc[0]
        record_login = {
                "log_id": int(log_id),
                "login_timestamp": None if pd.isna(row_enr.get("Login Timestamp")) else pd.to_datetime(row_enr.get("Login Timestamp")),
                "user_id": None if pd.isna(row_enr.get("User ID")) else int(row_enr.get("User ID")),
                "round_trip_time": None if pd.isna(row_enr.get("Round-Trip Time [ms]")) else float(row_enr.get("Round-Trip Time [ms]")),
                "ip_address": None if pd.isna(row_enr.get("IP Address")) else str(row_enr.get("IP Address")),
                "country": None if pd.isna(row_enr.get("Country")) else str(row_enr.get("Country")),
                "asn": None if pd.isna(row_enr.get("ASN")) else int(row_enr.get("ASN")),
                "user_agent": None if pd.isna(row_enr.get("User Agent String")) else str(row_enr.get("User Agent String")),
                "country_code": None if pd.isna(row_enr.get("countryCode")) else str(row_enr.get("countryCode")),
                "abuse_confidence_score": None if pd.isna(row_enr.get("abuseConfidenceScore")) else int(row_enr.get("abuseConfidenceScore")),
                "last_reported_at": None if pd.isna(row_enr.get("lastReportedAt")) else pd.to_datetime(row_enr.get("lastReportedAt")),
                "usage_type": None if pd.isna(row_enr.get("usageType")) else str(row_enr.get("usageType")),
                "domain": None if pd.isna(row_enr.get("domain")) else str(row_enr.get("domain")),
                "total_reports": None if pd.isna(row_enr.get("totalReports")) else int(row_enr.get("totalReports")),
        }
        print("Datos a insertar en login:", record_login)
        insert_login = """
        INSERT INTO login (
            log_id, login_timestamp, user_id, round_trip_time,
            ip_address, country, asn, user_agent,
            country_code, abuse_confidence_score, last_reported_at,
            usage_type, domain, total_reports
        )
        VALUES (
            %(log_id)s, %(login_timestamp)s, %(user_id)s, %(round_trip_time)s,
            %(ip_address)s, %(country)s, %(asn)s, %(user_agent)s,
            %(country_code)s, %(abuse_confidence_score)s, %(last_reported_at)s,
            %(usage_type)s, %(domain)s, %(total_reports)s
        )
        RETURNING id;
        """
        cur.execute(insert_login, record_login)
        login_id = cur.fetchone()[0]
        print("ID generado en login:", login_id)
        conn.commit()
        cur.close()
        conn.close()
        print(":marca_de_verificación_blanca: Inserción completada correctamente.")
    except Exception as e:
        print(f":x: Error insertando en PostgreSQL: {e}")

def tres_en_uno(dict):
    df_clean = clean_data_login2(dict)
    df_enriq = enrich_login_record(dict)
    insert_into_db_debug(df_clean, df_enriq)