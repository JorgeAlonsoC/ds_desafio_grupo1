import pandas as pd
import numpy as np
import psycopg2
from datetime import datetime
import matplotlib.pyplot as plt
import requests
import base64
import time
from collections import OrderedDict
from dotenv import load_dotenv
import os
import uuid

def limpieza_phishing(dict):
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

    insertar_phishing_enriquecido(df['URL'].iloc[0])

def dibujar_grafica():
    conn = psycopg2.connect(
            dbname="desafiogrupo1",
            user="desafiogrupo1_user",
            password="g7jS0htW8QqiGPRymmJw0IJgb04QO3Jy",
            host="dpg-d36i177fte5s73bgaisg-a.oregon-postgres.render.com",
            port="5432"
        )
        
    cur = conn.cursor()

    cur.execute("""
                SELECT indicators, COUNT(*) AS cantidad
                FROM logs
                WHERE indicators IN ('Correo seguro', 'Posible phishing')
                GROUP BY indicators;
            """)

    resultados = cur.fetchall()
        
    etiquetas = [r[0] for r in resultados]
    valores   = [r[1] for r in resultados]

    plt.figure()
    plt.pie(
            valores,
            labels=etiquetas,
            autopct=lambda p: f'{p:.0f}%' if p > 0 else '',
            startangle=90,
            wedgeprops={'width': 0.45}
            )
    plt.title('Distribución de indicadores')
    plt.axis('equal')
    plt.show()

    cur.close()
    conn.close()

load_dotenv()
VT_BASE = "https://www.virustotal.com/api/v3"
API_KEY = os.environ.get("VT_API_KEY")
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

def insertar_phishing_enriquecido(url):
    df = tablas_enriquecimiento_phishing(url)
    df['logs_id'] = (uuid.uuid4().int) %1_000_000

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