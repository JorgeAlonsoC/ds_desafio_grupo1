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

    # --- Conexión a PostgreSQL para insertar en tabla enriquecida ---
    try:
        conn = psycopg2.connect(
            dbname="desafiogrupo1",
            user="desafiogrupo1_user",
            password="tu_password",
            host="tu_host",
            port="5432"
        )
        cur = conn.cursor()
        
        # Preparar diccionario de la fila para insert
        row = df_enriq.iloc[0]
        record = {
            "log_id": row["log_id"],
            "login_timestamp": row.get("Login Timestamp"),
            "user_id": row.get("User ID"),
            "round_trip_time": row.get("Round-Trip Time [ms]"),
            "ip_address": row.get("IP Address"),  # la IP original
            "country": row.get("Country"),
            "asn": row.get("ASN"),
            "user_agent": row.get("User Agent String"),
            # Campos de la API (sin ipAddress)
            "country_code": row.get("countryCode"),
            "abuse_confidence_score": row.get("abuseConfidenceScore"),
            "last_reported_at": row.get("lastReportedAt"),
            "usage_type": row.get("usageType"),
            "domain": row.get("domain"),
            "total_reports": row.get("totalReports")
        }
        
        cur.execute("""
            INSERT INTO enriched_logs 
            (log_id, login_timestamp, user_id, round_trip_time, ip_address, country, asn, user_agent,
            country_code, abuse_confidence_score, last_reported_at, usage_type, domain, total_reports)
            VALUES (%(log_id)s, %(login_timestamp)s, %(user_id)s, %(round_trip_time)s, %(ip_address)s, %(country)s, %(asn)s, %(user_agent)s,
            %(country_code)s, %(abuse_confidence_score)s, %(last_reported_at)s, %(usage_type)s, %(domain)s, %(total_reports)s)
        """, record)
        
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error insertando en DB: {e}")
    
    return df_enriq