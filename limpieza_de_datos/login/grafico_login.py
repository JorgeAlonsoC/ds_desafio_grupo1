# pip install psycopg2-binary pandas matplotlib
from typing import Iterable, Optional, Tuple, Dict, Literal
import psycopg2
import pandas as pd
import matplotlib.pyplot as plt

def plot_indicadores(
    *,
    dbname: str = "desafiogrupo1",
    user: str = "desafiogrupo1_user",
    password: str = "g7jS0htW8QqiGPRymmJw0IJgb04QO3Jy",
    host: str = "dpg-d36i177fte5s73bgaisg-a.oregon-postgres.render.com",
    port: str = "5432",
    sslmode: str = "require",
    table: str = "public.logs",
    indicators: Iterable[str] = ("Robo de credenciales", "Cuenta comprometida", "Ataque fallido", "Log in válido"),
    order: Literal["fixed", "count_desc"] = "fixed",
    donut_width: float = 0.3,
    plot: bool = True,
    title_pie: str = "Distribución por indicadores",
    title_bar: str = "Conteo de incidentes por indicador",
    save_paths: Optional[Dict[str, str]] = None,
) -> Tuple[pd.DataFrame, Optional[plt.Figure], Optional[plt.Figure]]:
    """
    Consulta la tabla, agrega por 'indicators' y opcionalmente genera gráficos (donut % y barras conteo).

    Returns
    -------
    (df_group, fig_pie, fig_bar)
        df_group: DataFrame con columnas ['indicators', 'total']
        fig_pie:  Figure del donut si plot=True, si no None
        fig_bar:  Figure de barras si plot=True, si no None
    """
    indicators = tuple(indicators)
    if not indicators:
        raise ValueError("La lista de 'indicators' no puede estar vacía.")

    # placeholders (%s, %s, ...)
    placeholders = ", ".join(["%s"] * len(indicators))
    query = f"""
        SELECT *
        FROM {table}
        WHERE indicators IN ({placeholders});
    """

    # Mapa de colores solicitado
    color_map = {
        "Robo de credenciales": "red",
        "Cuenta comprometida": "orange",
        "Ataque fallido": "yellow",
        "Log in válido": "gray",
    }

    conn = None
    cur = None
    fig_pie = None
    fig_bar = None

    try:
        conn = psycopg2.connect(
            dbname=dbname,
            user=user,
            password=password,
            host=host,
            port=port,
            sslmode=sslmode,
        )
        cur = conn.cursor()

        # DataFrame con el filtro parametrizado
        df = pd.read_sql(query, conn, params=indicators)

        # Agregado
        df_group = (
            df.groupby("indicators")["severity"]
              .size()
              .reset_index(name="total")
        )

        # Orden
        if order == "fixed":
            indicador_order = list(indicators)
            df_group["indicators"] = pd.Categorical(
                df_group["indicators"], categories=indicador_order, ordered=True
            )
            df_group = df_group.sort_values("indicators").reset_index(drop=True)
        elif order == "count_desc":
            df_group = df_group.sort_values("total", ascending=False).reset_index(drop=True)
        else:
            raise ValueError("order debe ser 'fixed' o 'count_desc'.")

        if plot and not df_group.empty:
            # Colores alineados a df_group
            colors = [color_map.get(str(lbl), "#d3d3d3") for lbl in df_group["indicators"]]

            # --- Donut (%)
            fig_pie = plt.figure()
            wedges, texts, autotexts = plt.pie(
                df_group["total"],
                labels=df_group["indicators"].astype(str),
                colors=colors,
                autopct="%1.1f%%",
                wedgeprops=dict(width=donut_width),
                startangle=90,
                textprops={"color": "black", "fontsize": 10},
            )
            for t in autotexts:
                t.set_color("black")
                t.set_fontsize(10)

            plt.axis("equal")
            plt.title(title_pie, color="black")
            plt.tight_layout()
            if save_paths and "pie" in save_paths:
                fig_pie.savefig(save_paths["pie"], bbox_inches="tight")
            plt.show()

            # --- Barras (conteo absoluto)
            fig_bar = plt.figure()
            x = range(len(df_group))
            plt.bar(x, df_group["total"], tick_label=df_group["indicators"].astype(str), color=colors)

            plt.title(title_bar, color="black")
            plt.xlabel("Indicador", color="black")
            plt.ylabel("Conteo", color="black")
            plt.xticks(rotation=15)

            # etiquetas de conteo encima
            for xi, yi in zip(x, df_group["total"]):
                plt.text(xi, yi, str(yi), ha="center", va="bottom", fontsize=10, color="black")

            plt.tight_layout()
            if save_paths and "bar" in save_paths:
                fig_bar.savefig(save_paths["bar"], bbox_inches="tight")
            plt.show()

        return df_group, fig_pie, fig_bar

    finally:
        try:
            if cur is not None:
                cur.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


# --- Ejemplos de uso ---
# df_group, fig_pie, fig_bar = plot_indicadores(
#     indicators=("Robo de credenciales", "Cuenta comprometida", "Ataque fallido", "Log in válido"),
#     order="fixed",                  # o "count_desc"
#     donut_width=0.3,                # grosor del anillo (0.0 a 1.0)
#     plot=True,
#     save_paths={"pie": "pie.png", "bar": "bar.png"}
# )
# print(df_group)
