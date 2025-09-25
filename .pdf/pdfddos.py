from flask import Flask, request, send_file
from flask_cors import CORS
import io
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.platypus.flowables import HRFlowable
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4

app = Flask(__name__)
CORS(app)

@app.route("/download_pdf_ddos", methods=["POST"])
def download_pdf():
    data = request.get_json()

    # Extraer todos los campos
    log_id = data.get("Logs id", "Sin información adicional")
    destination_port = data.get("Destination Port", "Sin información adicional")
    flow_duration = data.get("Flow Duration", "Sin información adicional")
    total_fwd_packets = data.get("Total Fwd Packets", "Sin información adicional")
    total_backward_packets = data.get("Total Backward Packets", "Sin información adicional")
    flow_bytes_s = data.get("Flow Bytes/s", "Sin información adicional")
    flow_packets_s = data.get("Flow Packets/s", "Sin información adicional")
    fwd_packet_length_mean = data.get("Fwd Packet Length Mean", "Sin información adicional")
    fwd_packet_length_std = data.get("Fwd Packet Length Std", "Sin información adicional")
    min_packet_length = data.get("Min Packet Length", "Sin información adicional")
    max_packet_lengths = data.get("Max Packet Lengths", "Sin información adicional")
    flow_iat_mean = data.get("Flow IAT Mean", "Sin información adicional")
    flow_iat_std = data.get("Flow IAT Std", "Sin información adicional")
    syn_flag_count = data.get("SYN Flag Count", "Sin información adicional")
    ack_flag_count = data.get("ACK Flag Count", "Sin información adicional")
    down_up_ratio = data.get("Down/Up Ratio", "Sin información adicional")
    active_mean = data.get("Active Mean", "Sin información adicional")
    idle_mean = data.get("Idle Mean", "Sin información adicional")
    indicadores = data.get("Indicadores", "Sin información adicional")
    score = data.get("Score", "Sin información adicional")
    severity = data.get("Severity", "Sin información adicional")
    tipo = data.get("Tipo", "Sin información adicional")
    estandar = data.get("Estandar", "Sin información adicional")
    description = data.get("Description", "Sin información adicional")
    ataques_cves_tipicos = data.get("Ataques/CVEs tipicos", "Sin información adicional")
    como_proteger = data.get("Como proteger", "Sin información adicional")
    date = data.get("Date", "Sin información adicional")
    time = data.get("Time", "Sin información adicional")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    story_elements = []

    # Título y línea horizontal
    story_elements.append(Paragraph("INFORME DE ANÁLISIS DE FLUJO", styles["Heading2"]))
    story_elements.append(HRFlowable(width="100%", thickness=1))
    story_elements.append(Spacer(1, 24))

    # Cada campo en su propia línea
    story_elements.append(Paragraph(f"<b>Logs id:</b> {log_id}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Destination Port:</b> {destination_port}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Flow Duration:</b> {flow_duration}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Total Fwd Packets:</b> {total_fwd_packets}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Total Backward Packets:</b> {total_backward_packets}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Flow Bytes/s:</b> {flow_bytes_s}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Flow Packets/s:</b> {flow_packets_s}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Fwd Packet Length Mean:</b> {fwd_packet_length_mean}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Fwd Packet Length Std:</b> {fwd_packet_length_std}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Min Packet Length:</b> {min_packet_length}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Max Packet Lengths:</b> {max_packet_lengths}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Flow IAT Mean:</b> {flow_iat_mean}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Flow IAT Std:</b> {flow_iat_std}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>SYN Flag Count:</b> {syn_flag_count}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>ACK Flag Count:</b> {ack_flag_count}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Down/Up Ratio:</b> {down_up_ratio}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Active Mean:</b> {active_mean}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Idle Mean:</b> {idle_mean}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Indicadores:</b> {indicadores}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Score:</b> {score}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Severity:</b> {severity}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Tipo:</b> {tipo}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Estandar:</b> {estandar}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Description:</b> {description}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Ataques/CVEs tipicos:</b> {ataques_cves_tipicos}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Como proteger:</b> {como_proteger}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Date:</b> {date}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Time:</b> {time}", styles["Normal"]))

    doc.build(story_elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"Informe_{log_id.replace(' ', '_')}.pdf",
        mimetype="application/pdf"
    )

if __name__ == "__main__":
    app.run(debug=True)
