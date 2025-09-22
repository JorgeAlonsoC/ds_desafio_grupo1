#Pipeline_login.py
"""
Pipeline login = CSV -> limpieza -> JSON -> PostgreSQL
------------------------------------------------------
- Aplica a uno o varios CSV (lista o patrón glob).
- Deja payload EXACTO: ['type','indicators','severity','date','time'].
- Serializa a JSON (por archivo y opcional combinado).
- Inserta en BBDD usando el JSON generado.
- La BD completará columnas faltantes
"""

# ========= CONFIG =========
import os
from pathlib import Path

if "__file__" in globals():
    LOGIN_DIR = Path(__file__).resolve().parent
else:
    LOGIN_DIR = Path(os.getcwd())

# Entradas: lista de rutas o patrón glob
INPUTS         = str(LOGIN_DIR / "*.csv")
# Salidas dentro de /limpieza_de_datos/login
OUTPUT_DIR     = LOGIN_DIR / "salida"     # CSVs limpios
JSON_DIR       = LOGIN_DIR / "json"       # JSON por archivo
COMBINED_JSON  = "payload_combined.json"  # JSON combinado (en JSON_DIR). 
SUFFIX         = "_clean"
YEAR           = 2025
DB_TABLE       = "logs"                   # Tabla destino

# Credenciales BD (o usa env: PGDATABASE, PGUSER, PGPASSWORD, PGHOST, PGPORT)
DB_NAME      = "desafiogrupo1"
DB_USER      = "desafiogrupo1_user"
DB_PASSWORD  = "g7jS0htW8QqiGPRymmJw0IJgb04QO3Jy"
DB_HOST      = "dpg-d36i177fte5s73bgaisg-a.oregon-postgres.render.com"
DB_PORT      = "5432"
DB_PAGE_SIZE = 150
# ============================================

import glob, json
from datetime import datetime
from typing import List, Optional, Dict, Any

import numpy as np
import pandas as pd
import psycopg2
from psycopg2.extras import execute_batch


# ---------- Utilidades de limpieza ----------
def coerce_bool_series(s: pd.Series) -> pd.Series:
    """Convierte valores variados a booleano (sí/no, 1/0, true/false, si/sí…)."""
    if s.dtype == bool:
        return s
    mapping = {
        "true": True, "t": True, "1": True, "yes": True, "y": True, "si": True, "sí": True,
        "false": False, "f": False, "0": False, "no": False, "n": False,
    }
    def to_bool(x):
        if isinstance(x, (bool, np.bool_)):
            return bool(x)
        if pd.isna(x):
            return np.nan
        try:
            if isinstance(x, (int, np.integer)):
                return bool(int(x))
            return mapping.get(str(x).strip().lower(), np.nan)
        except Exception:
            return np.nan
    return s.apply(to_bool)


def replace_year_safe(ts: pd.Timestamp, year: int = 2025):
    """Reemplaza el año; si es 29-F y no es bisiesto, usa 28-F."""
    if pd.isna(ts):
        return ts
    try:
        return ts.replace(year=year)
    except ValueError:
        if ts.month == 2 and ts.day == 29:
            return ts.replace(month=2, day=28, year=year)
        return ts


def set_login_year(df: pd.DataFrame, col: str = "Login Timestamp", year: int = 2025) -> pd.DataFrame:
    """Convierte a datetime UTC y formatea ISO 8601 (YYYY-mm-ddTHH:MM:SSZ)."""
    if col not in df.columns:
        return df
    ts = pd.to_datetime(df[col], errors="coerce", utc=True).apply(lambda x: replace_year_safe(x, year))
    df[col] = ts.dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return df


def split_login_timestamp(df: pd.DataFrame, col: str = "Login Timestamp") -> pd.DataFrame:
    """
    Parte 'Login Timestamp' (ISO UTC) en 'date' (YYYY-MM-DD) y 'time' (HH:MM:SS).
    Si no existe o es inválido, deja None.
    """
    if col in df.columns:
        ts = pd.to_datetime(df[col], errors="coerce", utc=True)
        df["date"] = ts.dt.strftime("%Y-%m-%d").where(ts.notna(), None)
        df["time"] = ts.dt.strftime("%H:%M:%S").where(ts.notna(), None)
    else:
        df["date"] = None
        df["time"] = None
    return df


def add_severity(df: pd.DataFrame) -> pd.DataFrame:
    """
    Crea la columna numérica 'severity' según:
      3: Login Success=True,  Is Attack=True,  Is Account Takeover=True
      2: Login Success=True,  Is Attack=True,  Is Account Takeover=False
      1: Login Success=False, Is Attack=True,  Is Account Takeover=False
      0: Login Success=True,  Is Attack=False, Is Account Takeover=False
    Otros casos -> -1.
    """
    needed = ["Login Success", "Is Attack", "Is Account Takeover"]
    if not all(c in df.columns for c in needed):
        return df

    ls  = coerce_bool_series(df["Login Success"]).fillna(False)
    ia  = coerce_bool_series(df["Is Attack"]).fillna(False)
    iat = coerce_bool_series(df["Is Account Takeover"]).fillna(False)

    rojo     =  (ls)  & (ia) & (iat)
    naranja  =  (ls)  & (ia) & (~iat)
    amarillo = (~ls)  & (ia) & (~iat)
    blanco   =  (ls)  & (~ia) & (~iat)

    df["severity"] = np.select([rojo, naranja, amarillo, blanco], [3, 2, 1, 0], default=-1).astype(int)
    return df


def add_type_and_indicators(df: pd.DataFrame) -> pd.DataFrame:
    """
    Deriva 'type' e 'indicators' a partir de 'severity':
      type: 3->Incidencia | 1/2->Alerta | 0->Info
      indicators: 3->Robo de credenciales | 2->Cuenta comprometida | 1->Ataque fallido | 0->Log in válido
    """
    if "severity" not in df.columns:
        return df

    sev = pd.to_numeric(df["severity"], errors="coerce")

    df["type"] = np.select(
        [sev.eq(3), sev.isin([1, 2]), sev.eq(0)],
        ["Incidencia", "Alerta", "Info"],
        default="Info",
    )

    df["indicators"] = np.select(
        [sev.eq(3), sev.eq(2), sev.eq(1), sev.eq(0)],
        ["Robo de credenciales", "Cuenta comprometida", "Ataque fallido", "Log in válido"],
        default="",
    )

    return df


DEFAULT_DROP = [
    "index",
    "region",
    "city",
    "Browser Name and Version",
    "OS Name and Version",
    "Device Type",
    "Round-Trip Time [ms]",
]


def clean_any_csv(df: pd.DataFrame, year: int = 2025, drop_cols: Optional[List[str]] = None) -> pd.DataFrame:
    """
    Limpieza que deja el DF listo para la BD con columnas EXACTAS:
    ['type', 'indicators', 'severity', 'date', 'time']
    """
    drop_cols = drop_cols if drop_cols is not None else DEFAULT_DROP
    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")   # 1) quitar ruido
    df = set_login_year(df, "Login Timestamp", year)                                    # 2) normalizar año (ISO UTC)
    df = add_severity(df)                                                              # 3) calcular severity
    df = add_type_and_indicators(df)                                                   # 4) derivar type/indicators
    df = split_login_timestamp(df, "Login Timestamp")                                   # 5) crear date/time

    payload_cols = ["type", "indicators", "severity", "date", "time"]
    out = df.reindex(columns=payload_cols)

    out["severity"] = pd.to_numeric(out["severity"], errors="coerce").astype("Int64")
    out["date"] = out["date"].where(out["date"].notna() & (out["date"] != ""), None)
    out["time"] = out["time"].where(out["time"].notna() & (out["time"] != ""), None)
    return out


# ---------- E/S mínima ----------
def expand_inputs(inputs):
    """
    Acepta lista de rutas o patrón glob (str/Path).
    Devuelve rutas existentes (sin duplicados).
    """
    paths = []
    if isinstance(inputs, (list, tuple)):
        for p in inputs:
            paths.extend(glob.glob(str(p)))
    else:
        paths.extend(glob.glob(str(inputs)))

    out, seen = [], set()
    for p in paths:
        if os.path.isfile(p) and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def df_to_records(df: pd.DataFrame) -> List[dict]:
    """Reemplaza NaN/NaT por None y devuelve lista de diccionarios."""
    return df.where(pd.notnull(df), None).to_dict(orient="records")


def save_json(records: List[dict], path: str | Path) -> None:
    """Guarda records como JSON UTF-8 en la ruta dada."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(records, ensure_ascii=False), encoding="utf-8")


# ---------- Inserción en PostgreSQL desde JSON ----------
def insert_records(records: List[dict],
                   table: str,
                   dbname: Optional[str], user: Optional[str],
                   password: Optional[str], host: Optional[str],
                   port: Optional[str], page_size: int = 1000) -> None:
    """
    Inserta SOLO las columnas del payload (type, indicators, severity, date, time).
    La BD debe completar el resto con DEFAULT/NULL.
    """
    dbname   = dbname   or os.getenv("PGDATABASE")
    user     = user     or os.getenv("PGUSER")
    password = password or os.getenv("PGPASSWORD")
    host     = host     or os.getenv("PGHOST")
    port     = port     or os.getenv("PGPORT", "5432")

    if not table or not all([dbname, user, password, host, port]):
        print("[DB] Credenciales incompletas o tabla vacía. Se omite inserción.")
        return
    if not records:
        print("[DB] No hay registros para insertar.")
        return

    sql = f"""
        INSERT INTO {table} (type, indicators, severity, date, time)
        VALUES (%(type)s, %(indicators)s, %(severity)s, %(date)s, %(time)s)
    """

    with psycopg2.connect(dbname=dbname, user=user, password=password, host=host, port=port) as conn:
        with conn.cursor() as cur:
            execute_batch(cur, sql, records, page_size=page_size)
    print(f"[DB] Insertados {len(records)} registros en '{table}'.")


# ---------- MAIN ----------
def main():
    if not INPUTS or not OUTPUT_DIR:
        raise SystemExit("Config incompleta: define INPUTS y OUTPUT_DIR.")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    if JSON_DIR:
        JSON_DIR.mkdir(parents=True, exist_ok=True)

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

    # JSON combinado (opcional)
    if JSON_DIR and COMBINED_JSON:
        combined_path = JSON_DIR / COMBINED_JSON
        save_json(all_records, combined_path)
        print(f"[JSON] Combinado: {combined_path}")

    # Inserción a BBDD (desde JSON ya generado)
    if DB_TABLE:
        insert_records(
            all_records, DB_TABLE,
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD,
            host=DB_HOST, port=DB_PORT, page_size=DB_PAGE_SIZE
        )


if __name__ == "__main__":
    main()

