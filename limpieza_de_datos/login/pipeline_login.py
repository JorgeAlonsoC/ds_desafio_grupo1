#Pepiline_login.py
"""
Pipeline login = CSV -> limpieza -> JSON -> PostgreSQL
------------------------------------------------------
- Genera payload EXACTO para la tabla:
  [company_id, status, type, indicators, severity, date, time, actions_taken]
- Inserta en BD; 'id' lo genera la base de datos automáticamente.
"""

# ========= CONFIG =========
import os
from pathlib import Path

if "__file__" in globals():
    LOGIN_DIR = Path(__file__).resolve().parent
else:
    LOGIN_DIR = Path(os.getcwd())

INPUTS         = str(LOGIN_DIR / "df1_alimentacion.csv")
OUTPUT_DIR     = LOGIN_DIR / "salida"
JSON_DIR       = LOGIN_DIR / "json"
COMBINED_JSON  = "payload_combined.json"
SUFFIX         = "_clean"
YEAR           = 2025
DB_TABLE       = "logs"

# Valores fijos para nuevas columnas
COMPANY_ID  = 1
STATUS_VAL  = 1
ACTIONS_VAL = 1

# ============================================

import glob, json
from typing import List, Optional
import numpy as np
import pandas as pd
import psycopg2

# ---------- Utilidades de limpieza ----------
def coerce_bool_series(s: pd.Series) -> pd.Series:
    if s.dtype == bool:
        return s
    mapping = {
        "true": True, "t": True, "1": True, "yes": True, "y": True, "si": True, "sí": True,
        "false": False, "f": False, "0": False, "no": False, "n": False,
    }
    def to_bool(x):
        if isinstance(x, (bool, np.bool_)): return bool(x)
        if pd.isna(x): return np.nan
        try:
            if isinstance(x, (int, np.integer)): return bool(int(x))
            return mapping.get(str(x).strip().lower(), np.nan)
        except Exception:
            return np.nan
    return s.apply(to_bool)

def replace_year_safe(ts: pd.Timestamp, year: int = 2025):
    if pd.isna(ts): return ts
    try: return ts.replace(year=year)
    except ValueError:
        if ts.month == 2 and ts.day == 29: return ts.replace(month=2, day=28, year=year)
        return ts

def set_login_year(df: pd.DataFrame, col: str = "Login Timestamp", year: int = 2025) -> pd.DataFrame:
    if col not in df.columns: return df
    ts = pd.to_datetime(df[col], errors="coerce", utc=True).apply(lambda x: replace_year_safe(x, year))
    df[col] = ts.dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return df

def split_login_timestamp(df: pd.DataFrame, col: str = "Login Timestamp") -> pd.DataFrame:
    if col in df.columns:
        ts = pd.to_datetime(df[col], errors="coerce", utc=True)
        df["date"] = ts.dt.strftime("%Y-%m-%d").where(ts.notna(), None)
        df["time"] = ts.dt.strftime("%H:%M:%S").where(ts.notna(), None)
    else:
        df["date"] = None; df["time"] = None
    return df

def add_severity(df: pd.DataFrame) -> pd.DataFrame:
    needed = ["Login Success","Is Attack","Is Account Takeover"]
    if not all(c in df.columns for c in needed): return df
    ls  = coerce_bool_series(df["Login Success"]).fillna(False)
    ia  = coerce_bool_series(df["Is Attack"]).fillna(False)
    iat = coerce_bool_series(df["Is Account Takeover"]).fillna(False)
    rojo     =  (ls) & (ia) & (iat)
    naranja  =  (ls) & (ia) & (~iat)
    amarillo = (~ls) & (ia) & (~iat)
    blanco   =  (ls) & (~ia) & (~iat)
    df["severity"] = np.select([rojo,naranja,amarillo,blanco],[3,2,1,0], default=-1).astype(int)
    return df

def add_type_and_indicators(df: pd.DataFrame) -> pd.DataFrame:
    if "severity" not in df.columns: return df
    sev = pd.to_numeric(df["severity"], errors="coerce")
    df["type"] = np.select([sev.eq(3), sev.isin([1,2]), sev.eq(0)], ["Incidencia","Alerta","Info"], default="Info")
    df["indicators"] = np.select(
        [sev.eq(3), sev.eq(2), sev.eq(1), sev.eq(0)],
        ["Robo de credenciales","Cuenta comprometida","Ataque fallido","Log in válido"], default=""
    )
    return df

DEFAULT_DROP = ["index","region","city","Browser Name and Version","OS Name and Version","Device Type","Round-Trip Time [ms]"]

def clean_any_csv(df: pd.DataFrame, year: int = 2025, drop_cols: Optional[List[str]] = None) -> pd.DataFrame:
    drop_cols = drop_cols if drop_cols is not None else DEFAULT_DROP
    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")
    df = set_login_year(df, "Login Timestamp", year)
    df = add_severity(df)
    df = add_type_and_indicators(df)
    df = split_login_timestamp(df, "Login Timestamp")

    # Asegurar defaults si faltan
    if "severity" not in df.columns:
        df["severity"] = 1
    df["severity"] = pd.to_numeric(df["severity"], errors="coerce").fillna(1).astype(int)
    if "type" not in df.columns:
        df["type"] = "Info"
    df["type"] = df["type"].fillna("Info").astype(str)
    if "indicators" not in df.columns:
        df["indicators"] = ""
    df["indicators"] = df["indicators"].fillna("").astype(str)

    # columnas exactas del payload base
    payload_cols = ["type","indicators","severity","date","time"]
    out = df.reindex(columns=payload_cols)

    # Normalizar date/time
    out["date"] = out["date"].where(out["date"].notna() & (out["date"] != ""), None)
    out["time"] = out["time"].where(out["time"].notna() & (out["time"] != ""), None)

    # columnas fijas
    out["company_id"]    = COMPANY_ID
    out["status"]        = STATUS_VAL
    out["actions_taken"] = ACTIONS_VAL

    # reordenar como la tabla (sin 'id')
    return out[["company_id","status","type","indicators","severity","date","time","actions_taken"]]

# ---------- E/S ----------
def expand_inputs(inputs):
    paths = []
    if isinstance(inputs, (list, tuple)):
        for p in inputs: paths.extend(glob.glob(str(p)))
    else:
        paths.extend(glob.glob(str(inputs)))
    out, seen = [], set()
    for p in paths:
        if os.path.isfile(p) and p not in seen:
            seen.add(p); out.append(p)
    return out

def df_to_records(df: pd.DataFrame) -> List[dict]:
    return df.where(pd.notnull(df), None).to_dict(orient="records")

def save_json(records: List[dict], path: str | Path) -> None:
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(records, ensure_ascii=False), encoding="utf-8")

# ---------- Inserción en PostgreSQL ----------
def insert_records(records: List[dict], table: str = "logs") -> None:
    """
    Inserta las columnas:
    (company_id, status, type, indicators, severity, date, time, actions_taken).
    """
    if not records:
        print("[DB] No hay registros para insertar.")
        return

    # Conexión EXACTA solicitada
    conn = psycopg2.connect(
        dbname="desafiogrupo1",
        user="desafiogrupo1_user",
        password="g7jS0htW8QqiGPRymmJw0IJgb04QO3Jy",
        host="dpg-d36i177fte5s73bgaisg-a.oregon-postgres.render.com",
        port="5432"
    )

    try:
        cur = conn.cursor()

        # Asegurar keys y defaults
        safe_records = []
        for r in records:
            safe_records.append({
                "company_id":    r.get("company_id", COMPANY_ID),
                "status":        r.get("status", STATUS_VAL),
                "type":          r.get("type", "Info"),
                "indicators":    r.get("indicators", ""),
                "severity":      int(r.get("severity", 1)) if r.get("severity") is not None else 1,
                "date":          r.get("date"),   # None -> NULL si la BD lo permite o tiene default
                "time":          r.get("time"),   # None -> NULL si la BD lo permite o tiene default
                "actions_taken": r.get("actions_taken", ACTIONS_VAL),
            })

        cur.executemany(f"""
            INSERT INTO {table} (company_id, status, type, indicators, severity, date, time, actions_taken)
            VALUES (%(company_id)s, %(status)s, %(type)s, %(indicators)s, %(severity)s, %(date)s, %(time)s, %(actions_taken)s)
        """, safe_records)

        conn.commit()
        print(f"[DB] Insertados {len(safe_records)} registros en '{table}'.")
    finally:
        try:
            cur.close()
        except Exception:
            pass
        conn.close()

# ---------- MAIN ----------
def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    if JSON_DIR: JSON_DIR.mkdir(parents=True, exist_ok=True)

    input_paths = expand_inputs(INPUTS)
    if not input_paths:
        raise SystemExit("No se encontraron archivos de entrada.")

    all_records: List[dict] = []
    for src in input_paths:
        try:
            df = pd.read_csv(src)
            df_clean = clean_any_csv(df, year=YEAR)

            base = Path(src).stem
            out_csv = OUTPUT_DIR / f"{base}{SUFFIX}.csv"
            df_clean.to_csv(out_csv, index=False, encoding="utf-8")
            print(f"[OK] {src} -> {out_csv} ({len(df)} filas -> {len(df_clean)} filas)")

            records = df_to_records(df_clean)
            all_records.extend(records)

            if JSON_DIR:
                json_path = JSON_DIR / f"{base}{SUFFIX}_dbpayload.json"
                save_json(records, json_path)
                print(f"[JSON] Guardado: {json_path}")

        except Exception as e:
            print(f"[ERROR] {src}: {e}")

    if JSON_DIR and COMBINED_JSON:
        combined_path = JSON_DIR / COMBINED_JSON
        save_json(all_records, combined_path)
        print(f"[JSON] Combinado: {combined_path}")

    # Inserción a BBDD
    insert_records(all_records, table=DB_TABLE)

if __name__ == "__main__":
    main()
