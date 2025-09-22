# Pipeline
"""
Pipeline de limpieza
-------------------------------------------
- Aplica la misma lógica a **cualquier** CSV (uno o varios a la vez).
- Normaliza "Login Timestamp" al año indicado (por defecto, 2025).
- Añade columna numérica 'severity' (3=Rojo, 2=Naranja, 1=Amarillo, 0=Blanco, -1=Indeterminado).
- Elimina columnas ruido configurables.
- Registro en BBDD (mapeado al esquema) y exportación JSON.
"""

import hashlib
import json
import os
from typing import List, Tuple, Optional, Dict, Any

import numpy as np
import pandas as pd
from sqlalchemy import create_engine  # pip install sqlalchemy

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


def add_severity(df: pd.DataFrame) -> pd.DataFrame:
    """
    Agrega columna numérica 'severity' según:
      - 3 (Rojo):     Login Success=True,  Is Attack=True,  Is Account Takeover=True
      - 2 (Naranja):  Login Success=True,  Is Attack=True,  Is Account Takeover=False
      - 1 (Amarillo): Login Success=False, Is Attack=True,  Is Account Takeover=False
      - 0 (Blanco):   Login Success=True,  Is Attack=False, Is Account Takeover=False
    Otros casos: -1 (indeterminado si hay NaN en cualquiera de los tres flags).
    """
    needed = ["Login Success", "Is Attack", "Is Account Takeover"]
    if not all(c in df.columns for c in needed):
        return df

    ls  = coerce_bool_series(df["Login Success"])  
    ia  = coerce_bool_series(df["Is Attack"])      
    iat = coerce_bool_series(df["Is Account Takeover"])

    mask_valid = ls.notna() & ia.notna() & iat.notna()

    # Sustitutos seguros para evaluar reglas sólo donde hay datos válidos
    ls_f, ia_f, iat_f = ls.fillna(False), ia.fillna(False), iat.fillna(False)

    rojo     =  mask_valid & (ls_f)  & (ia_f) & (iat_f)
    naranja  =  mask_valid & (ls_f)  & (ia_f) & (~iat_f)
    amarillo =  mask_valid & (~ls_f) & (ia_f) & (~iat_f)
    blanco   =  mask_valid & (ls_f)  & (~ia_f) & (~iat_f)

    severity = np.select(
        [rojo,  naranja,  amarillo,  blanco],
        [3,     2,        1,         0],
        default=-1
    ).astype(int)

    df["severity"] = severity
    return df


def drop_columns(df: pd.DataFrame, cols_to_drop: List[str]) -> pd.DataFrame:
    """Elimina columnas si existen (ignora si faltan)."""
    return df.drop(columns=[c for c in cols_to_drop if c in df.columns], errors="ignore")


def row_fingerprint(row: pd.Series) -> str:
    """Hash estable por fila: ordena claves y omite derivadas/auxiliares."""
    skip_prefixes = ("criticidad",)  # compat histórica
    skip_exact = {"severity", "_row_hash"}  # derivadas que no deben afectar
    items = []
    for k in sorted(row.index, key=lambda x: str(x).lower()):
        if k in skip_exact:
            continue
        kl = str(k).lower()
        if any(kl.startswith(p) for p in skip_prefixes):
            continue
        v = row[k]
        items.append(f"{k}={'"' if pd.isna(v) else str(v)}")
    blob = "\x1f".join(items)
    return hashlib.sha1(blob.encode("utf-8", errors="ignore")).hexdigest()


def incremental_register(df_clean: pd.DataFrame, state_path: str, train_out: str) -> Tuple[int, int]:
    """Añade solo filas nuevas a train_out basándose en hash por fila. Devuelve (nuevas, agregadas_esta_vez)."""
    seen = set()
    if os.path.exists(state_path):
        with open(state_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    seen.add(json.loads(line)["hash"])
                except Exception:
                    continue

    hashes = df_clean.apply(row_fingerprint, axis=1)
    df_clean = df_clean.assign(_row_hash=hashes)
    new_rows_df = df_clean[~df_clean["_row_hash"].isin(seen)].copy()

    total_before = 0
    if os.path.exists(train_out):
        try:
            existing = pd.read_csv(train_out)
            total_before = len(existing)
            combined = pd.concat([existing, new_rows_df.drop(columns=["_row_hash"])], ignore_index=True)
        except Exception:
            combined = new_rows_df.drop(columns=["_row_hash"])
    else:
        combined = new_rows_df.drop(columns=["_row_hash"])
    combined.to_csv(train_out, index=False, encoding="utf-8")

    if not new_rows_df.empty:
        os.makedirs(os.path.dirname(state_path) or ".", exist_ok=True)
        with open(state_path, "a", encoding="utf-8") as f:
            for h in new_rows_df["_row_hash"].tolist():
                f.write(json.dumps({"hash": h}) + "\n")

    return len(new_rows_df), len(combined) - total_before


# ---------------- Limpieza genérica ----------------
DEFAULT_DROP = [
    "index",
    "region",
    "Round-Trip Time [ms]",
    "city",
    "Browser Name and Version",
    "OS Name and Version",
    "Device Type",
]


def clean_any_csv(df: pd.DataFrame, year: int = 2025, drop_cols: Optional[List[str]] = None) -> pd.DataFrame:
    """Limpieza genérica y enriquecimiento."""
    drop_cols = drop_cols if drop_cols is not None else DEFAULT_DROP
    df = drop_columns(df, drop_cols)
    df = set_login_year(df, "Login Timestamp", year)
    df = add_severity(df)
    return df


# ---------------- Mapeo al esquema de BBDD ----------------

def map_to_db_schema(df_clean: pd.DataFrame) -> pd.DataFrame:
    """
    Adapta el DF limpio al esquema de la BBDD:
      columnas_db_sql: [id; company_id; status; type; indicators; severity; date; time; actions_taken]
    La BBDD rellena: id, company_id, status, actions_taken
    Enviamos: type, indicators, severity, date, time

    Reglas:
      severity = severity
      type:
        3 -> "Incidencia"
        2/1 -> "Alerta"
        0 -> "Info"
      indicators:
        3 -> "Account Takeover"
        2 -> "Cuenta comprometida"
        1 -> "Ataque fallido"
        0 -> "Log in válido"
      Login Timestamp -> date(YYYY-MM-DD), time(HH:MM:SS)
    """
    if "severity" not in df_clean.columns:
        raise ValueError("No se encontró 'severity' en el DataFrame limpio.")

    severity = pd.to_numeric(df_clean["severity"], errors="coerce")

    type_series = np.select(
        [severity.eq(3), severity.isin([1, 2]), severity.eq(0)],
        ["Incidencia", "Alerta", "Info"],
        default="Info",
    )

    indicators = np.select(
        [severity.eq(3), severity.eq(2), severity.eq(1), severity.eq(0)],
        ["Account Takeover", "Cuenta comprometida", "Ataque fallido", "Log in válido"],
        default="",
    )

    if "Login Timestamp" in df_clean.columns:
        ts = pd.to_datetime(df_clean["Login Timestamp"], errors="coerce", utc=True)
        date_str = ts.dt.strftime("%Y-%m-%d").where(ts.notna(), "")
        time_str = ts.dt.strftime("%H:%M:%S").where(ts.notna(), "")
    else:
        date_str = pd.Series("", index=df_clean.index)
        time_str = pd.Series("", index=df_clean.index)

    df_db = pd.DataFrame({
        "type": type_series.astype(str),
        "indicators": indicators.astype(str),
        "severity": severity.astype("Int64"),  # permite nulos
        "date": date_str,
        "time": time_str,
    })
    return df_db


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
      - suffix: str = "_clean"           # sufijo de salida
      - year: int = 2025                 # año para Login Timestamp
      - drop_cols: Optional[List[str]]   # columnas a eliminar (por defecto DEFAULT_DROP)
      - json_out_dir: Optional[str]      # carpeta para exportar registros a JSON (opcional)
      - train_out: Optional[str]         # CSV acumulado de entrenamiento (opcional)
      - state_file: Optional[str]        # archivo JSONL con hashes (requerido si train_out)
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
    train_out   = config.get("train_out", None)
    state_file  = config.get("state_file", None)
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
    cleaned_paths = []
    for inp in inputs:
        try:
            df = pd.read_csv(inp)
            df_clean = clean_any_csv(df, year=year, drop_cols=drop_cols)

            base = os.path.splitext(os.path.basename(inp))[0]
            out_csv = os.path.join(outdir, f"{base}{suffix}.csv")
            df_clean.to_csv(out_csv, index=False, encoding="utf-8")
            print(f"[OK] {inp} -> {out_csv} ({len(df)} filas -> {len(df_clean)} filas)")
            cleaned_paths.append(out_csv)

            # b) Construir payload para la BBDD (mapeo al esquema)
            df_db = map_to_db_schema(df_clean)
            records_db = df_to_records(df_db)
            print(f"[DB-PAYLOAD] {base}: {len(records_db)} registros -> columnas {list(df_db.columns)}")

            # c) Guardar JSON del payload de BBDD
            if json_dir:
                json_path = os.path.join(json_dir, f"{base}{suffix}_dbpayload.json")
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(records_db, f, ensure_ascii=False)
                print(f"[JSON] Payload BBDD guardado: {json_path}")

            # d) Enviar a BBDD
            if use_db:
                try:
                    send_to_db(
                        df_db,                 # enviamos SOLO las columnas del esquema
                        db_url=db_url,
                        table=db_table,
                        if_exists=db_if_exist,
                        chunksize=db_chunks,
                        echo=db_echo,
                    )
                    print(f"[DB] Insertados {len(df_db)} registros en '{db_table}'.")
                except Exception as e:
                    print(f"[DB][ERROR] {base}: {e}")

        except Exception as e:
            print(f"[ERROR] {inp}: {e}")

    # --- Registro incremental global sobre el CSV limpio ---
    if train_out:
        if not state_file:
            raise SystemExit("Se especificó 'train_out' pero falta 'state_file' para el incremental.")
        all_new = 0
        all_appended = 0
        for out_csv in cleaned_paths:
            try:
                dfc = pd.read_csv(out_csv)
                new_rows, appended = incremental_register(dfc, state_file, train_out)
                all_new += new_rows
                all_appended += appended
            except Exception as e:
                print(f"[WARN] Incremental falló para {out_csv}: {e}")
        print(f"[INCREMENTAL] Nuevas totales: {all_new}. Agregadas esta vez: {all_appended}. Train: {train_out}")
