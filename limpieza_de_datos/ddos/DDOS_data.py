import pandas as pd
from datetime import datetime
import psycopg2



def clean_data(archive_dic):
    df = pd.DataFrame(archive_dic)
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
            "type": row["Type"],
            "indicators": row["Indicators"],
            "severity": row["Severity"],
            "date": row["Date"],
            "time": row["Time"]
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









