import pandas as pd
import numpy as np
import psycopg2
from datetime import datetime

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
    df['time'] = now.strftime("H%:%M:%S")
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
            "type": row['type'],
            "indicators": row['indicators'],
            "severity": row['severity'],
            "date": row['date'],
            "time": row['time']
        }
        for _, row in df.iterrows()
    ]

    cur.executemany("""
        INSERT INTO logs (type, indicators, severity, date, time)
        VALUES (%(type)s, %(indicators)s, %(severity)s, %(date)s, %(time)s)
    """, records)
    conn.commit()
    cur.close()
    conn.close()

