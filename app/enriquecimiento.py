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
    df_id = pd.DataFrame([record_dict])
    
    # Llamada API para la IP del registro
    ip = df_id.get("IP Address", [None])[0]
    if not ip:
        return df_id  # No hay IP que enriquecer
    
    api_info = check_ip_info(ip)
    
    # Añadir las columnas de la API al DataFrame
    for k, v in api_info.items():
        if k != "ipAddress":  # ya tenemos IP en 'IP Address'
            df_id[k] = v

    
    return df_id