import plotly.express as px
import plotly.io as pio
import psycopg2
import pandas as pd
import seaborn as sns
import json

def graf_ddos():
    # Conexión a la base de datos
    conn = psycopg2.connect(
        dbname="desafiogrupo1",
        user="desafiogrupo1_user",
        password="g7jS0htW8QqiGPRymmJw0IJgb04QO3Jy",
        host="dpg-d36i177fte5s73bgaisg-a.oregon-postgres.render.com",
        port="5432"
    )

    query = """
    SELECT *
    FROM public.logs
    WHERE indicators IN ('BENIGN', 'XSS', 'Brute Force', 'Sql Injection');
    """
    df = pd.read_sql(query, conn)
    conn.close()

    # Agrupar
    df_group = df.groupby('indicators')['severity'].size().reset_index(name='total')

    # Paleta de colores en formato hex
    colors = [f"rgb({int(r*255)}, {int(g*255)}, {int(b*255)})"
              for r, g, b in sns.color_palette("pastel", len(df_group))]

    # Crear gráfica
    fig = px.pie(
        df_group,
        values="total",
        names="indicators",
        title="Distribución de Incidentes",
        color="indicators",
        color_discrete_sequence=colors,
        hole=0.7
    )

    # Convertir a JSON (dict)
    fig_dict = json.loads(pio.to_json(fig))
    return fig_dict

if __name__ == "__main__":
    app.run(debug=True)
