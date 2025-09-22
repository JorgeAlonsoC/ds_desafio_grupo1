# main.py
from limpieza_de_datos.login.pipeline_login import run_pipeline

config = {
    "inputs": [
        r"C:\proyecto\data\entrada\df1_alimentacion.csv",
        r"C:\proyecto\data\entrada\df2_prueba.csv",
    ],
    "output_dir": r"C:\Users\karla\OneDrive\Documentos\GitHub\ds_desafio_grupo1\limpieza_de_datos\login\salida",
    "suffix": "_clean",
    "year": 2025,
    # "drop_cols": ["index","region","city","Browser Name and Version","OS Name and Version","Device Type"],
    # "json_out_dir": r"C:\proyecto\data\json",
    # "train_out": r"C:\proyecto\data\modelo\training_acumulado.csv",
    # "state_file": r"C:\proyecto\data\modelo\.cleaning_state.jsonl",
    # "db_url": "postgresql+psycopg2://usuario:password@host:5432/mi_db",
    # "db_table": "eventos_login",
    # "db_if_exists": "append",   # append | replace | fail
    # "db_chunksize": 2000,
    # "db_echo": False,
}

run_pipeline(config)