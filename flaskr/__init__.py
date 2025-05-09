from pathlib import Path
from flask import Flask, flash, request, redirect, url_for, session
from flask_session import Session
from redis import Redis
from werkzeug.utils import secure_filename
import subprocess
from eleVADR import Assessor

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'pcap'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

SESSION_TYPE = 'redis'
SESSION_REDIS = Redis(host='localhost', port=6379)
app.config.from_object(__name__)
Session(app)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            uploaded_filepath = Path(app.config['UPLOAD_FOLDER'], filename)
            session['uploaded_filepath'] = str(uploaded_filepath)
            file.save(uploaded_filepath)
            return redirect('/complete')
    return '''
    <!doctype html>
    <title>Upload File for Analysis</title>
    <h1>Upload a .pcap file here</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    '''

@app.route('/complete')
def run_analysis():
    elevadr = Assessor(path_to_pcap=session.get('uploaded_filepath', None),
                       path_to_zeek="zeeks",
                       path_to_zeek_scripts="zeek_scripts")
    elevadr.run_analysis()
    report = elevadr.generate_report()
    return f'''
    <!doctype html>
    <title>Successful Uploads</title>
    <h1>Complete!</h1>
    {report}
    '''