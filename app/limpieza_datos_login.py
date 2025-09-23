import pandas as pd
import numpy as np
import uuid
import psycopg2 

def clean_data_login(archive_dic):
    # Convertir a DataFrame
    df = pd.DataFrame([archive_dic])
    df.columns = df.columns.str.strip()

    # --- Selección de columnas relevantes para el dashboard ---
    keep_cols = [
        "Login Timestamp", "Login Successful",
        "Is Attack IP", "Is Account Takeover"
    ]
    df_front = df[[c for c in keep_cols if c in df.columns]].copy()

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

    df["Severity"] = np.select([rojo, naranja, amarillo, blanco],[3,2,1,0], default=1).astype(int)

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
    df_front["log_id"] = ["Log" + uuid.uuid4().hex for _ in range(len(df_front))]
    df["log_id"] = df_front["log_id"]

    # ---  Conexión a PostgreSQL para pruebas ---
    
    conn = psycopg2.connect(
        dbname="desafiogrupo1",
        user="desafiogrupo1_user",
        password="tu_password",
        host="tu_host",
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
        } for _, row in df.iterrows()
    ]

    cur.executemany("""
        INSERT INTO logs (log_id, company_id, type, indicators, severity, date, time, actions_taken)
        VALUES (%(log_id)s, %(company_id)s, %(type)s, %(indicators)s, %(severity)s, %(date)s, %(time)s, %(actions_taken)s)
    """, records)

    conn.commit()
    cur.close()
    conn.close()
    

    # --- Preparar tabla enriquecida ---
    df_id = df.copy()

    return df_front, df_id

