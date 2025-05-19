from pathlib import Path
import os
from flask import Flask, flash, request, redirect, url_for, session
from flask_session import Session
from werkzeug.utils import secure_filename
import subprocess

from app.utils.eleVADR import Assessor

# Declare the project root directory ("app", in this case) for relative paths
PROJECT_ROOT = Path(__file__).resolve().parent
UPLOAD_DIR = str(Path(PROJECT_ROOT, "data/uploads"))
ZEEK_OUTPUT_DIR = str(Path(PROJECT_ROOT, "data/zeeks"))
ZEEK_SCRIPTS_DIR = str(Path(PROJECT_ROOT, "data/zeek_scripts"))

ALLOWED_EXTENSIONS = {"pcap"}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app.secret_key = "g32NXqJSFibVS150Op4ugg"  # NOT A REAL SECRET KEY - This is solely for development purposes
app.config.from_object(__name__)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/", methods=["GET", "POST"])
def upload_file():
    print(UPLOAD_DIR, ZEEK_OUTPUT_DIR, ZEEK_SCRIPTS_DIR)
    if request.method == "POST":
        # check if the post request has the file part
        if "file" not in request.files:
            flash("No file part")
            return redirect(request.url)
        file = request.files["file"]
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == "":
            flash("No selected file")
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            uploaded_filepath = Path(app.config["UPLOAD_FOLDER"], filename)
            session["uploaded_filepath"] = str(uploaded_filepath)
            if filename in os.listdir(app.config["UPLOAD_FOLDER"]):
                os.remove(str(uploaded_filepath))
            file.save(uploaded_filepath)
            return redirect("/report")
    return """
    <!doctype html>
    <title>Upload File for Analysis</title>
    <h1>Upload a .pcap file here</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type=submit value=Upload>
    </form>
    """


@app.route("/report")
def run_analysis():
    elevadr = Assessor(
        path_to_pcap=session.get("uploaded_filepath", None),
        path_to_zeek=ZEEK_OUTPUT_DIR,
        path_to_zeek_scripts=ZEEK_SCRIPTS_DIR,
    )
    elevadr.run_analysis()
    report = elevadr.generate_report()
    return f"""
    <!doctype html>
    <title>Successful Uploads</title>
    <h1>Complete!</h1>
    {report}
    """
