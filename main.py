import json
import uuid

from bson import json_util, ObjectId
from flask import Flask, render_template, request, url_for, redirect, session, jsonify
import pymongo
import bcrypt
import boto3, botocore
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "testing"
client = pymongo.MongoClient("mongodb://localhost:27017")
db = client.get_database('SpotDraft')
records = db.register
files = db['files']
app.config['S3_BUCKET'] = "pdfmanagementsystem"
app.config['S3_KEY'] = "#####################"
app.config['S3_SECRET'] = "##########################"
app.config['S3_LOCATION'] = 'http://{}.s3.amazonaws.com/'.format('pdfmanagementsystem')
s3 = boto3.client(
    "s3",
    aws_access_key_id=app.config['S3_KEY'],
    aws_secret_access_key=app.config['S3_SECRET']
)
ALLOWED_EXTENSIONS = {'pdf'}


@app.route("/sign-in", methods=["POST", "GET"])
def index():
    message = ''
    if "email" in session:
        return jsonify({'message': "alreagy_logged_in"})
    if request.method == "POST":
        data = request.get_json()
        user = data["fullname"]
        email = data["email"]

        password1 = data["password1"]
        password2 = data["password2"]

        user_found = records.find_one({"name": user})
        email_found = records.find_one({"email": email})
        if user_found:
            message = 'There already is a user by that name'
            return jsonify({'message': message})
        if email_found:
            message = 'This email already exists in database'
            return jsonify({'message': message})
        if password1 != password2:
            message = 'Passwords should match!'
            return jsonify({'message': message})
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            user_input = {'name': user, 'email': email, 'password': hashed}
            records.insert_one(user_input)

            user_data = records.find_one({"email": email})
            new_email = user_data['email']
            message = "user registered with " + new_email
            return jsonify({'message': message})
    return jsonify({'message': 'You Are at Login Page'})


@app.route("/login", methods=["POST", "GET"])
def login():
    message = 'Please login to your account'
    if "email" in session:
        return jsonify({'message': 'Already logged_in'})

    if request.method == "POST":
        data = request.get_json()
        email = data["email"]
        password = data["password"]

        email_found = records.find_one({"email": email})
        if email_found:
            email_val = email_found['email']
            password_check = email_found['password']

            if bcrypt.checkpw(password.encode('utf-8'), password_check):
                session["email"] = email_val
                return jsonify({'message': 'logged_in'})
            else:
                if "email" in session:
                    return redirect(url_for("logged_in"))
                message = 'Wrong password'
                return jsonify({'message': message})
        else:
            message = 'Email not found'
            return jsonify({'message': message})
    return jsonify({'message': message})


@app.route('/reset-password', methods=['POST'])
def reset_password():
    # Extract the necessary data from the request
    data = request.get_json()
    email = data["email"]
    new_password = data['new_password']
    user = records.find_one({'email': email})
    if user:
        hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        records.update_one({'email': email}, {'$set': {'password': hashed}})
        response = {'message': 'Password reset successful'}
        return jsonify(response), 200
    else:
        response = {'message': 'User not found'}
        return jsonify(response), 404


@app.route("/logout", methods=["POST", "GET"])
def logout():
    if "email" in session:
        session.pop("email", None)
        return jsonify({'message': "You have been signed out"})
    else:
        return jsonify({'message': "In Session"})


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/upload-file", methods=["GET", "POST"])
def upload_file():
    if "email" in session:
        if request.method == "POST":
            uploaded_file = request.files["file-to-save"]
            if not allowed_file(uploaded_file.filename):
                return "FILE NOT ALLOWED!"
            new_filename = uuid.uuid4().hex + '.' + uploaded_file.filename.rsplit('.', 1)[1].lower()
            bucket_name = "pdfmanagementsystem"
            s3 = boto3.resource('s3',
                                aws_access_key_id=app.config['S3_KEY'],
                                aws_secret_access_key=app.config['S3_SECRET'])
            s3.Bucket(bucket_name).upload_fileobj(uploaded_file, new_filename)
            file_data = {
                's3_file_name': new_filename,
                's3_url': f"https://{bucket_name}.s3.amazonaws.com/{new_filename}",
                'original_filename': uploaded_file.filename,
                'filename': new_filename,
                'bucket': bucket_name,
                'region': 'Asia Pacific (Mumbai) ap-south-1'
            }
            files.insert_one(file_data)
            return jsonify({"data": file_data})
        return jsonify({"message": "file upload failed"})
    return jsonify({'message': "You have been signed out"})


@app.route("/get-file", methods=["GET", "POSt"])
def get_file():
    if "email" in session:
        if request.method == "POST":
            data = request.get_json()
            if data["search"] is None or data["search"] == '':
                all_files = list(files.find({}))
                all_files = json.loads(json_util.dumps(all_files))
                return jsonify({
                    "count": len(all_files),
                    "data": all_files
                })
            else:
                query = {'original_filename': {'$regex': 'e'}}
                all_files = list(files.find(query))
                all_files = json.loads(json_util.dumps(all_files))
                return jsonify({
                    "count": len(all_files),
                    "data": all_files
                })
    return jsonify({'message': "You have been signed out"})


@app.route("/delete-file", methods=["DELETE"])
def delete_file():
    # if "email" in session:
    document_id = request.get_json()["id"]
    file = files.find_one({"_id": ObjectId(document_id)})
    bucket_name = "pdfmanagementsystem"
    s3 = boto3.client('s3',
                      aws_access_key_id=app.config['S3_KEY'],
                      aws_secret_access_key=app.config['S3_SECRET'])
    s3_file_name = file['s3_file_name']
    s3.delete_object(Bucket=bucket_name, Key=s3_file_name)
    files.delete_one({"_id": ObjectId(document_id)})
    return jsonify({'message': "Record has been deleted"})


# return jsonify({'message': "You have been signed out"})


# end of code to run it
if __name__ == "__main__":
    app.run(debug=True)
