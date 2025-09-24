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