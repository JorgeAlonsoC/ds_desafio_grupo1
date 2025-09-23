import pandas as pd
import requests
import time
import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
HEADERS = {"Accept": "application/json", "Key": API_KEY}

def check_ip_info(ip, pause=1.0):
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
    # Convertir a DataFrame de una fila
    df_enriq = pd.DataFrame([record_dict])
    
    # Llamada API para la IP del registro
    ip = df_enriq.at[0, "IP Address"]
    api_info = check_ip_info(ip)
    
    # Añadir las columnas de la API al DataFrame
    for k, v in api_info.items():
        if k != "ipAddress":  # ya tenemos IP en 'IP Address'
            df_enriq[k] = v

    
    return df_enriq