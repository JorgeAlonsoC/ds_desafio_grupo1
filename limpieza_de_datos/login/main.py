# main.py
from borrador_pipeline import run_pipeline

config = {
    # CSV de entrada (pueden ser 1..N ficheros)
    "inputs": [
        r"C:\proyecto\data\entrada\df1_alimentacion.csv",
        r"C:\proyecto\data\entrada\df2_prueba.csv",
    ],
    # Carpeta donde guardaremos los CSV limpios
    "output_dir": r"C:\proyecto\data\salida",
    "suffix": "_clean",
    "year": 2025,

    # (Opcional) columnas a eliminar; si lo omites, usa las por defecto
    # "drop_cols": ["index","region","city","Browser Name and Version","OS Name and Version","Device Type"],

    # (Opcional) exportar también JSON de los registros (lista de diccionarios)
    # "json_out_dir": r"C:\proyecto\data\json",

    # (Opcional) registro incremental (solo añade filas nuevas)
    # Recomendado si alimentarás un dataset acumulado para ML
    # "train_out": r"C:\proyecto\data\modelo\training_acumulado.csv",
    # "state_file": r"C:\proyecto\data\modelo\.cleaning_state.jsonl",

    # (Opcional) Envío a BBDD
    # "db_url": "postgresql+psycopg2://usuario:password@host:5432/mi_db",
    # "db_table": "eventos_login",
    # "db_if_exists": "append",   # append | replace | fail
    # "db_chunksize": 2000,
    # "db_echo": False,
}

run_pipeline(config)