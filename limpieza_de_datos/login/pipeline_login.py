# Pipeline
"""
Pipeline de limpieza
-------------------------------------------
- Aplica la misma lógica a **cualquier** CSV (uno o varios a la vez).
- Normaliza "Login Timestamp" al año indicado (por defecto, 2025).
- Añade columna numérica 'severity' (3=Rojo, 2=Naranja, 1=Amarillo, 0=Blanco, -1=Indeterminado).
- Elimina columnas ruido configurables.
- Envía a BBDD (PostgreSQL en Render) y exporta JSON del payload final.
- El DataFrame limpio ya queda con las columnas EXACTAS de la BD que enviamos:
  ['type', 'indicators', 'severity', 'date', 'time']
"""

import json
import os
from typing import List, Optional, Dict, Any

import numpy as np
import pandas as pd
from sqlalchemy import create_engine
import psycopg2

# ---------------- Utilidades ----------------
def coerce_bool_series(s: pd.Series) -> pd.Series:
    """Convierte valores varios a booleanos: yes/no, 0/1, true/false, si/sí, etc."""
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
            s = str(x).strip().lower()
            return mapping.get(s, np.nan)
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
    ts = pd.to_datetime(df[col], errors="coerce", utc=True)
    ts = ts.apply(lambda x: replace_year_safe(x, year))
    df[col] = ts.dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return df


def split_login_timestamp(df: pd.DataFrame, col: str = "Login Timestamp") -> pd.DataFrame:
    """
    Parte 'Login Timestamp' (ISO UTC) en 'date' (YYYY-MM-DD) y 'time' (HH:MM:SS).
    Si no existe o es inválido, usa cadenas vacías.
    """
    if col in df.columns:
        ts = pd.to_datetime(df[col], errors="coerce", utc=True)
        df["date"] = ts.dt.strftime("%Y-%m-%d").where(ts.notna(), "")
        df["time"] = ts.dt.strftime("%H:%M:%S").where(ts.notna(), "")
    else:
        df["date"] = ""
        df["time"] = ""
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
        return df  # no podemos calcular; devolvemos tal cual

    ls  = coerce_bool_series(df["Login Success"]).fillna(False)
    ia  = coerce_bool_series(df["Is Attack"]).fillna(False)
    iat = coerce_bool_series(df["Is Account Takeover"]).fillna(False)

    rojo     =  (ls)  & (ia) & (iat)
    naranja  =  (ls)  & (ia) & (~iat)
    amarillo = (~ls)  & (ia) & (~iat)
    blanco   =  (ls)  & (~ia) & (~iat)

    df["severity"] = np.select(
        [rojo,  naranja,  amarillo,  blanco],
        [3,     2,        1,         0],
        default=-1
    ).astype(int)
    return df


def add_type_and_indicators(df: pd.DataFrame) -> pd.DataFrame:
    """
    Deriva 'type' e 'indicators' a partir de 'severity':
      type:
        3 -> "Incidencia"
        2/1 -> "Alerta"
        0 -> "Info"
      indicators:
        3 -> "Account Takeover"
        2 -> "Cuenta comprometida"
        1 -> "Ataque fallido"
        0 -> "Log in válido"
    """
    if "severity" not in df.columns:
        return df

    sev = pd.to_numeric(df["severity"], errors="coerce")

    df["type"] = np.select(
        [sev.eq(3), sev.isin([1, 2]), sev.eq(0)],
        ["Incidencia", "Alerta", "Info"],
        default="Info",
    ).astype(str)

    df["indicators"] = np.select(
        [sev.eq(3), sev.eq(2), sev.eq(1), sev.eq(0)],
        ["Account Takeover", "Cuenta comprometida", "Ataque fallido", "Log in válido"],
        default="",
    ).astype(str)

    return df


def drop_columns(df: pd.DataFrame, cols_to_drop: List[str]) -> pd.DataFrame:
    """Elimina columnas si existen (ignora si faltan)."""
    return df.drop(columns=[c for c in cols_to_drop if c in df.columns], errors="ignore")


# ---------------- Limpieza genérica ----------------
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
    df = drop_columns(df, drop_cols)                 # 1) quitar ruido
    df = set_login_year(df, "Login Timestamp", year) # 2) normalizar año (ISO UTC)
    df = add_severity(df)                            # 3) calcular severity
    df = add_type_and_indicators(df)                 # 4) derivar type/indicators
    df = split_login_timestamp(df, "Login Timestamp")# 5) crear date/time

    # 6) devolver SOLO las columnas de la BD que enviamos
    payload_cols = ["type", "indicators", "severity", "date", "time"]
    out = df.reindex(columns=payload_cols)

    # dtype entero con nulos permitido para 'severity' si hiciera falta:
    out["severity"] = pd.to_numeric(out["severity"], errors="coerce").astype("Int64")
    return out


# ---------------- BBDD helpers ----------------
def df_to_records(df: pd.DataFrame) -> List[dict]:
    """Convierte el DataFrame a lista de diccionarios (orient='records')."""
    return df.to_dict(orient="records")


def send_to_db(df: pd.DataFrame, db_url: str, table: str,
               if_exists: str = "append", chunksize: int = 1000, echo: bool = False) -> None:
    """
    Inserta el DataFrame en la BBDD usando pandas.to_sql.
      - db_url: URL SQLAlchemy
      - table: nombre de tabla
      - if_exists: 'append' | 'replace' | 'fail'
      - chunksize: tamaño de lote para inserciones
    """
    engine = create_engine(db_url, echo=echo, future=True)
    df.to_sql(name=table, con=engine, if_exists=if_exists, index=False, chunksize=chunksize, method="multi")


# ---------------- Runner ----------------
def run_pipeline(config: Dict[str, Any]) -> None:
    """
    Ejecuta el pipeline con un diccionario de configuración.

    Keys esperadas en config:
      - inputs: List[str]                # rutas a CSV de entrada (obligatorio)
      - output_dir: str                  # carpeta de salida para CSV limpios (obligatorio)
      - suffix: str = "_clean"           # sufijo de salida para CSV limpio (opcional)
      - year: int = 2025                 # año para Login Timestamp
      - drop_cols: Optional[List[str]]   # columnas a eliminar (por defecto DEFAULT_DROP)
      - json_out_dir: Optional[str]      # carpeta para exportar registros a JSON del payload BBDD (opcional)
      - db_url: Optional[str]            # URL SQLAlchemy (opcional)
      - db_table: Optional[str]          # tabla destino (opcional)
      - db_if_exists: str = "append"     # 'append' | 'replace' | 'fail'
      - db_chunksize: int = 1000         # tamaño de lote inserciones
      - db_echo: bool = False            # log detallado de SQLAlchemy
    """
    inputs      = config.get("inputs", [])
    outdir      = config.get("output_dir", "")
    suffix      = config.get("suffix", "_clean")
    year        = int(config.get("year", 2025))
    drop_cols   = config.get("drop_cols", None)
    json_dir    = config.get("json_out_dir", None)
    db_url      = config.get("db_url", None)
    db_table    = config.get("db_table", None)
    db_if_exist = config.get("db_if_exists", "append")
    db_chunks   = int(config.get("db_chunksize", 1000))
    db_echo     = bool(config.get("db_echo", False))

    if not inputs or not outdir:
        raise ValueError("Faltan 'inputs' y/o 'output_dir' en la configuración.")

    os.makedirs(outdir or ".", exist_ok=True)
    if json_dir:
        os.makedirs(json_dir, exist_ok=True)

    use_db = bool(db_url and db_table)

    # --- Procesado de entradas ---
    for inp in inputs:
        try:
            # 1) Leer y limpiar
            df = pd.read_csv(inp)
            df_clean = clean_any_csv(df, year=year, drop_cols=drop_cols)

            # 2) Guardar CSV limpio (payload final con columnas de BD)
            base = os.path.splitext(os.path.basename(inp))[0]
            out_csv = os.path.join(outdir, f"{base}{suffix}.csv")
            df_clean.to_csv(out_csv, index=False, encoding="utf-8")
            print(f"[OK] {inp} -> {out_csv} ({len(df)} filas -> {len(df_clean)} filas)")

            # 3) Guardar JSON del payload (opcional)
            if json_dir:
                json_path = os.path.join(json_dir, f"{base}{suffix}_dbpayload.json")
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(df_to_records(df_clean), f, ensure_ascii=False)
                print(f"[JSON] Payload BBDD guardado: {json_path}")

            # 4) Enviar a BBDD (opcional)
            if use_db:
                try:
                    send_to_db(
                        df_clean,           
                        db_url=db_url,
                        table=db_table,
                        if_exists=db_if_exist,
                        chunksize=db_chunks,
                        echo=db_echo,
                    )
                    print(f"[DB] Insertados {len(df_clean)} registros en '{db_table}'.")
                except Exception as e:
                    print(f"[DB][ERROR] {base}: {e}")

        except Exception as e:
            print(f"[ERROR] {inp}: {e}")


# ── Config BBDD (PostgreSQL en Render) ─────────────────────────────────

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
        "type": row["type"],
        "indicators": row["indicators"],
        "severity": row["severity"],
        "date": row["date"],
        "time": row["time"]
    }
    for _, row in df.iterrows()
]

cur.executemany("""
    INSERT INTO data_app (type, indicators, severity, date, time)
    VALUES (%(type)s, %(indicators)s, %(severity)s, %(date)s, %(time)s)
""", records)

conn.commit()
cur.close()
conn.close()
