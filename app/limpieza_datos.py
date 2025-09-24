import pandas as pd
from datetime import datetime
import psycopg2
import numpy as np
import requests
import time
import os
from dotenv import load_dotenv
import uuid

load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
HEADERS = {"Accept": "application/json", "Key": API_KEY}

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
        "Web Attack ´?¢ Sql Injection": "Incidencia",
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
    
    now = datetime.now()
    df["Date"] = now.date()
    df["Time"] = now.strftime("%H:%M:%S")


    df["ddos_id"] = ["DDos" + str(uuid.uuid4().int) ]

    
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
            "id" = row['ddos_id'],
            "company_id": 1,
            "type": row['Tipo'],
            "indicators": row['Indicadores'],
            "severity": row['Severity'],
            "date": row['Date'],
            "time": row['Time'],
            "actions_taken": 1
        }
        for _, row in df.iterrows()
    ]
    

    cur.executemany("""
        INSERT INTO logs (company_id, type, indicators, severity, date, time, actions_taken)
        VALUES (%(company_id)s, %(type)s, %(indicators)s, %(severity)s, %(date)s, %(time)s, %(actions_taken)s)
    """, records)

    conn.commit()
    cur.close()
    conn.close()



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
    df_r = df[['HasPopup',
               'Nivel3_Alta',
               'Nivel2_Media',
               'Nivel1_Baja',
               'type',
               'indicators',
               'severity',
               'date',
               'time']]

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
        INSERT INTO logs (company_id, type, indicators, severity, date, time, actions_taken)
        VALUES (%(company_id)s, %(type)s, %(indicators)s, %(severity)s, %(date)s, %(time)s, %(actions_taken)s)
    """, records)
    conn.commit()
    cur.close()
    conn.close()



def clean_data_login(archive_dic):
    # Convertir a DataFrame
    df = pd.DataFrame([archive_dic])
    df.columns = df.columns.str.strip()

    # --- Selección de columnas relevantes ---
    keep_cols = [
        "Login Timestamp", "Login Successful",
        "Is Attack IP", "Is Account Takeover"
    ]
    df_front = df[[c for c in keep_cols if c in df.columns]]

    # --- Normalizar timestamp y fijar año 2025 ---
    ts = pd.to_datetime(df["Login Timestamp"], errors="coerce", utc=True)
    ts = ts.apply(lambda x: x.replace(year=2025) if pd.notna(x) else x)
    df["Date"] = ts.dt.date
    df["Time"] = ts.dt.strftime("%H:%M:%S")

    # --- Severidad ---
    ls  = df.get("Login Successful", pd.Series([False])).fillna(False).astype(bool)
    ia  = df.get("Is Attack IP", pd.Series([False])).fillna(False).astype(bool)
    iat = df.get("Is Account Takeover", pd.Series([False])).fillna(False).astype(bool)

    rojo     = (ls) & (ia) & (iat)
    naranja  = (ls) & (ia) & (~iat)
    amarillo = (~ls) & (ia) & (~iat)
    blanco   = (ls) & (~ia) & (~iat)

    df["Severity"] = np.select([rojo,naranja,amarillo,blanco],[3,2,1,0], default=1).astype(int)

    # --- Tipo ---
    df["Tipo"] = np.select(
        [df["Severity"].eq(3), df["Severity"].isin([1,2]), df["Severity"].eq(0)],
        ["Incidencia","Alerta","Info"], default="Info"
    )

    # --- Indicadores ---
    df["Indicadores"] = np.select(
        [df["Severity"].eq(3), df["Severity"].eq(2), df["Severity"].eq(1), df["Severity"].eq(0)],
        ["Robo de credenciales","Cuenta comprometida","Ataque fallido","Login válido"], default=""
    )

    # --- ASIGNAR log_id ---
    df_front["log_id"] = ["Log" + str(uuid.uuid4().int) ]
    df["log_id"] = df_front["log_id"]

        # --- Preparar tabla enriquecida ---
    df_id = df.copy()


    from enriquecimiento import check_ip_info, enrich_login_record


    # --- Conexión a PostgreSQL ---
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
            "log_id": row["log_id"],
            "company_id": 1,
            "type": row["Tipo"],
            "indicators": row["Indicadores"],
            "severity": int(row["Severity"]),
            "date": row["Date"],
            "time": row["Time"],
            "actions_taken": 1
        }
        for _, row in df.iterrows()
    ]

    cur.executemany("""
        INSERT INTO logs (log_id, company_id, type, indicators, severity, date, time, actions_taken)
        VALUES (%(log_id)s, %(company_id)s, %(type)s, %(indicators)s, %(severity)s, %(date)s, %(time)s, %(actions_taken)s)
    """, records)

    conn.commit()
    cur.close()
    conn.close()

    df_id = enrich_login_record(df_id.iloc[0].to_dict())

    """    # --- Conexión a PostgreSQL para insertar en tabla enriquecida ---
    try:
        conn = psycopg2.connect(
            dbname="desafiogrupo1",
            user="desafiogrupo1_user",
            password="g7jS0htW8QqiGPRymmJw0IJgb04QO3Jy",
            host="dpg-d36i177fte5s73bgaisg-a.oregon-postgres.render.com",
            port="5432"
        )
        cur = conn.cursor()
        
        # Preparar diccionario de la fila para insert
        row = df_id.iloc[0]
        record = {
            "log_id": row["log_id"],
            "login_timestamp": row.get("Login Timestamp")if pd.notna(row.get("Login Timestamp")) else None,
            "user_id": None if pd.isna(row.get("User ID")) else row.get("User ID"),
            "round_trip_time": None if pd.isna(row.get("Round-Trip Time [ms]")) else row.get("Round-Trip Time [ms]"),
            "ip_address": None if pd.isna(row.get("IP Address")) else row.get("IP Address"),
            "country": None if pd.isna(row.get("Country")) else row.get("Country"),
            "asn": None if pd.isna(row.get("ASN")) else row.get("ASN"),
            "user_agent": None if pd.isna(row.get("User Agent String")) else row.get("User Agent String"),
            "country_code": None if pd.isna(row.get("countryCode")) else row.get("countryCode"),
            "abuse_confidence_score": None if pd.isna(row.get("abuseConfidenceScore")) else row.get("abuseConfidenceScore"),
            "last_reported_at": row.get("lastReportedAt")if pd.notna(row.get("lastReportedAt")) else None,
            "usage_type": None if pd.isna(row.get("usageType")) else row.get("usageType"),
            "domain": None if pd.isna(row.get("domain")) else row.get("domain"),
            "total_reports": None if pd.isna(row.get("totalReports")) else row.get("totalReports"),
        }
        
        cur.execute("""
            INSERT INTO enriched_logs 
            (log_id, login_timestamp, user_id, round_trip_time, ip_address, country, asn, user_agent,
            country_code, abuse_confidence_score, last_reported_at, usage_type, domain, total_reports)
            VALUES (%(log_id)s, %(login_timestamp)s, %(user_id)s, %(round_trip_time)s, %(ip_address)s, %(country)s, %(asn)s, %(user_agent)s,
            %(country_code)s, %(abuse_confidence_score)s, %(last_reported_at)s, %(usage_type)s, %(domain)s, %(total_reports)s)
            ON CONFLICT (log_id) DO NOTHING
        """, record)
        
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error insertando en DB: {e}")"""
    





