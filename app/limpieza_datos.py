import pandas as pd
from datetime import datetime
import psycopg2
import numpy as np

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






