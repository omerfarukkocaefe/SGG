from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
import os
import json
import csv
from datetime import datetime
from fpdf import FPDF
import uuid


from crawler import crawl_for_sqli  # crawler.py dosyasını import et
from sqli_scan import test_error_based, test_boolean_based, test_time_based


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'csv', 'json'}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Mock database for demonstration
reports_db = {}

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'SQL Injection Scan Report', 0, 1, 'C')
        self.ln(5)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_pdf_report(report_data):
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font('Arial', '', 12)
    
    # Report metadata
    pdf.cell(0, 10, f"Scan Date: {report_data['scan_date']}", 0, 1)
    pdf.cell(0, 10, f"Target URL: {report_data['target_url']}", 0, 1)
    pdf.cell(0, 10, f"Scan Mode: {report_data['scan_mode']}", 0, 1)
    pdf.ln(10)
    
    # Vulnerabilities section
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Vulnerabilities Found:', 0, 1)
    pdf.set_font('Arial', '', 10)
    
    for vuln in report_data['vulnerabilities']:
        pdf.multi_cell(0, 8, f"- {vuln['type']} at {vuln['url']}\n   Payload: {vuln['payload']}\n   Evidence: {vuln['evidence']}", 0, 1)
        pdf.ln(2)
    
    # Summary
    pdf.ln(10)
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, f"Summary: {len(report_data['vulnerabilities'])} vulnerabilities found", 0, 1)
    
    # Save the PDF
    report_id = str(uuid.uuid4())
    filename = f"report_{report_id}.pdf"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    pdf.output(filepath)
    
    return filename

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def start_scan():
    target_url = request.form.get('target_url')
    scan_mode = request.form.get('scan_mode')
    custom_parameters = request.form.get('custom_parameters', '').split(',')
    
    urls_file = request.files.get('urls_file')
    file_path = None
    
    if urls_file and allowed_file(urls_file.filename):
        filename = secure_filename(urls_file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        urls_file.save(file_path)
    
    if file_path:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f.readlines() if line.strip()]
    else:
        urls = [target_url]
    
    vulnerabilities = []

    # Her URL için crawler çalıştır
    for url in urls:
        sqli_urls = crawl_for_sqli(url, max_pages=30)  # Crawl yap
        for sqli_url in sqli_urls:
            vulnerabilities.append({
                'type': 'SQL Injection (Crawled)',
                'url': sqli_url,
                'payload': "Payload bulunmadı - sadece parametreli URL",
                'evidence': "Parametre bulundu ('?' ve '=')"
            })

    report_data = {
        'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'target_url': target_url,
        'scan_mode': scan_mode,
        'parameters': custom_parameters,
        'vulnerabilities': vulnerabilities
    }
    
    report_id = str(uuid.uuid4())
    reports_db[report_id] = report_data

    return jsonify({
        'status': 'success',
        'report_id': report_id,
        'vulnerabilities_found': len(vulnerabilities)
    })


@app.route('/report/<report_id>')
def view_report(report_id):
    if report_id not in reports_db:
        return "Report not found", 404
    
    return render_template('report.html', report=reports_db[report_id], report_id=report_id)

@app.route('/export/<report_id>/<format>')
def export_report(report_id, format):
    if report_id not in reports_db:
        return "Report not found", 404
    
    report_data = reports_db[report_id]
    
    if format == 'json':
        filename = f"report_{report_id}.json"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(filepath, 'w') as f:
            json.dump(report_data, f)
        return send_file(filepath, as_attachment=True)
    
    elif format == 'csv':
        filename = f"report_{report_id}.csv"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Prepare CSV data
        with open(filepath, 'w', newline='') as csvfile:
            fieldnames = ['type', 'url', 'payload', 'evidence']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for vuln in report_data['vulnerabilities']:
                writer.writerow(vuln)
        
        return send_file(filepath, as_attachment=True)
    
    elif format == 'pdf':
        filename = generate_pdf_report(report_data)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        return send_file(filepath, as_attachment=True)
    
    elif format == 'html':
        return render_template('export_report.html', report=report_data)
    
    return "Invalid format", 400

if __name__ == '__main__':
    app.run(debug=True)
