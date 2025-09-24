from flask import Flask, request, send_file
from flask_cors import CORS
import io
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4

# Crear la app
app = Flask(__name__)
CORS(app)

# Endpoint 
@app.route("/download-pdf", methods=["POST"])
def download_pdf():
    data = request.get_json()

    log_id = data.get("log_id", "Sin información adicional")
    login_timestamp = data.get("login_timestamp", "Sin información adicional")
    user_id = data.get("user_id", "Sin información adicional")
    round_trip_time = data.get("round_trip_time", "Sin información adicional")
    ip_address = data.get("ip_address", "Sin información adicional")
    country = data.get("country", "Sin información adicional")
    asn = data.get("asn", "Sin información adicional")
    user_agent = data.get("user_agent", "Sin información adicional")
    country_code = data.get("country_code", "Sin información adicional")
    abuse_confidence_score = data.get("abuse_confidence_score", "Sin información adicional")
    last_reported_at = data.get("last_reported_at", "Sin información adicional")
    usage_type = data.get("usage_type", "Sin información adicional")
    domain = data.get("domain", "Sin información adicional")
    total_reports = data.get("total_reports", "Sin información adicional")

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    story_elements = []
    story_elements.append(Paragraph("INFORME DE LOGIN", styles["Heading2"]))
    story_elements.append(Spacer(1, 24))

    story_elements.append(Paragraph(f"<b>Log_id:</b> {log_id}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Login_timestamp:</b> {login_timestamp}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>User Id:</b> {user_id}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Round Trip Time:</b> {round_trip_time}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>IP Address:</b> {ip_address}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Country:</b> {country}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>ASN:</b> {asn}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>User Agent:</b> {user_agent}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Country Code:</b> {country_code}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Abuse Confidence Score:</b> {abuse_confidence_score}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Last Reported At:</b> {last_reported_at}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Usage Type:</b> {usage_type}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Domain:</b> {domain}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Total Reports:</b> {total_reports}", styles["Normal"]))

    doc.build(story_elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"Informe_{log_id.replace(' ', '_')}.pdf",
        mimetype="application/pdf"
    )

# Arrancar el servidor
if __name__ == "__main__":
    app.run(debug=True)