from flask import request, Flask, jsonify
import psycopg2
import os
import pandas as pd
import random 
from flask_cors import CORS
from datetime import datetime
from limpieza_datos import *
from graficos import graf_ddos


app = Flask(__name__)
app.config["DEBUG"] = True
CORS(app)

def malware_type_detection(dict):
    if 'FILENAME' in dict.keys():
        clean_data_phishing(dict)
    elif 'Destination Port' in dict.keys():
        clean_data_ddos(dict)
    else:
        clean_data_login(dict)

def procesamiento_datos():
    login_list =[]
    df_int_login = pd.read_csv("https://desafiogrupo1.s3.us-east-1.amazonaws.com/df1_alimentacion.csv")
    df_ddos = pd.read_csv("https://desafiogrupo1.s3.us-east-1.amazonaws.com/df_alimentacion_DDOS.csv")
    df_phishing = pd.read_csv("https://desafiogrupo1.s3.us-east-1.amazonaws.com/df_alimentacion_phising.csv")

    for i in range(df_int_login.shape[0]):
        login_list.append(df_int_login.iloc[i].to_dict())

    for i in range(df_ddos.shape[0]):
        login_list.append(df_ddos.iloc[i].to_dict())

    for i in range(df_phishing.shape[0]):
        login_list.append(df_phishing.iloc[i].to_dict())

    random.shuffle(login_list)

    for i in range(len(login_list)):
        malware_type_detection(login_list[i])
    return "Success"
    

@app.route("/", methods= ["GET"])
def main():
    return jsonify(procesamiento_datos())

@app.route("/download_pdf", methods= ["POST"])
def download_pdf():
    import requests
    from flask import send_file, request
    import io


    from flask import Flask, request, jsonify, send_file, send_from_directory
    from flask_cors import CORS
    from datetime import datetime
    import os
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.enums import TA_JUSTIFY
    data = request.get_json()
    theme = data.get("theme", "Sin tema")
    character = data.get("character", "Sin personaje")
    tone = data.get("tone", "Normal")
    story = data.get("story", "")

    buffer = io.BytesIO()
    
    # Documento A4 con márgenes
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    justify_style = ParagraphStyle(
        'Justify',
        parent=styles['Normal'],
        alignment=TA_JUSTIFY,
        leading=15 
    )

    story_elements = []
    story_elements.append(Paragraph(f"<b>Tema:</b> {theme}", styles["Heading3"]))
    story_elements.append(Paragraph(f"<b>Personaje:</b> {character}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Tono:</b> {tone}", styles["Normal"]))
    story_elements.append(Spacer(1, 12))

    # Convertir saltos de línea en <br/> para que respeten el formato
    story_html = story.replace("\n", "<br/>")
    story_elements.append(Paragraph("<b>Cuento:</b>", styles["Heading3"]))
    story_elements.append(Paragraph(story_html, justify_style))

    doc.build(story_elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"cuento_{theme.replace(' ', '_')}.pdf",
        mimetype="application/pdf"
    )

@app.route("/grafico_ddos", methods= ["POST"])
def grafico_ddos():
    return jsonify(graf_ddos())


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
