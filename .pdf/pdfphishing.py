from flask import Flask, request, send_file
from flask_cors import CORS
import io
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.platypus.flowables import HRFlowable

# Crear la app
app = Flask(__name__)
CORS(app)

# Endpoint 
@app.route("/download-pdf", methods=["POST"])
def download_pdf():
    data = request.get_json()

    logs_id = data.get("logs_id", "Sin información adicional")
    url = data.get("url", "Sin información adicional")
    status = data.get("status", "Sin información adicional")
    malicious = data.get("malicious", "Sin información adicional")
    suspicious = data.get("suspicious", "Sin información adicional")
    undetected = data.get("undetected", "Sin información adicional")
    harmless = data.get("harmless", "Sin información adicional")
    timeout = data.get("timeout", "Sin información adicional")
    whois = data.get("whois", "Sin información adicional")
    tags = data.get("tags", "Sin información adicional")
    dns_records = data.get("dns_records", "Sin información adicional")
    last_dns_records_date = data.get("last_dns_records_date", "Sin información adicional")
    registrar = data.get("registrar", "Sin información adicional")
    expiration_date = data.get("expiration_date", "Sin información adicional")
    tld = data.get("tld", "Sin información adicional")
    issuer = data.get("issuer", "Sin información adicional")
    subject_CN = data.get("subject_CN", "Sin información adicional")
    cert_not_before = data.get("cert_not_before", "Sin información adicional")
    cert_not_after = data.get("cert_not_after", "Sin información adicional")
    cert_key_size = data.get("cert_key_size", "Sin información adicional")
    thumbprint_sha256 = data.get("thumbprint_sha256", "Sin información adicional")
    reputation = data.get("reputation", "Sin información adicional")
    popularity_ranks = data.get("popularity_ranks", "Sin información adicional")
    jarm = data.get("jarm", "Sin información adicional")
    categories = data.get("categories", "Sin información adicional")


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
    story_elements.append(Paragraph("INFORME DE ANÁLISIS DE URL", styles["Heading2"]))
    story_elements.append(HRFlowable(width="100%", thickness=1))
    story_elements.append(Spacer(1, 24))

    story_elements.append(Paragraph(f"<b>Logs id:</b> {logs_id}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Url:</b> {url}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Status:</b> {status}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Malicious:</b> {malicious}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Suspicious:</b> {suspicious}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Undetected:</b> {undetected}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Harmless:</b> {harmless}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Timeout:</b> {timeout}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Whois:</b> {whois}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Tags:</b> {tags}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Dns Records:</b> {dns_records}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Last dns records_date:</b> {last_dns_records_date}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Registrar:</b> {registrar}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Expiration_date:</b> {expiration_date}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>TLD:</b> {tld}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Issuer:</b> {issuer}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Subject CN:</b> {subject_CN}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Cert not Before:</b> {cert_not_before}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Cert not After:</b> {cert_not_after}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Cert Key Size:</b> {cert_key_size}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Thumbprint Sha256:</b> {thumbprint_sha256}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Reputation:</b> {reputation}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Popularity Ranks:</b> {popularity_ranks}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Jarm:</b> {jarm}", styles["Normal"]))
    story_elements.append(Paragraph(f"<b>Categories:</b> {categories}", styles["Normal"]))

    doc.build(story_elements)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"Informe_{logs_id.replace(' ', '_')}.pdf",
        mimetype="application/pdf"
    )

# Arrancar el servidor
if __name__ == "__main__":
    app.run(debug=True)