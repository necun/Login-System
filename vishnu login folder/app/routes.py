from utils import *
from db_operations import *

@app.route('/user/signup', methods=['POST'])
def signup():
    try:
        data = request.json

        required_fields = ['fullname', 'username', 'password', 'email', 'phone_number']
        missing_fields = [field for field in required_fields if field not in data or not data[field]]

        if missing_fields:
            return jsonify({'message': 'Missing fields', 'missing': missing_fields}), 400

        fullname = data['fullname']
        username = data['username']
        password = generate_password_hash(data['password']).decode('utf-8')
        email = data['email']
        phone_number = str(data['phone_number'])

        if not re.match(email_regex, email, re.IGNORECASE):
            return jsonify({"error": "Not a valid email"}), 400

        if not re.match(phone_number_regex, phone_number):
            return jsonify({"error": "Not a valid phone number"}), 400

        if check_user_exists(username, email, phone_number):
            return jsonify({'message': 'Username or email or phone number already exists'}), 400

        verification_token = secrets.token_hex(16)
        
        subject = 'Email Verification'
        body = f"http://localhost:5000/user/verify_email/{verification_token}"
        recipient = email

        send_email(subject, recipient, body)

        update_email_verify(fullname, username, password, email, phone_number, verification_token)

        return jsonify({'message': f'Verification link has been sent to {email}'}), 202

    except Exception as e:
        return jsonify({'message': 'Internal Server Error', 'error': str(e)}), 500
    
@app.route('/user/verify_email/<token>', methods=['GET'])
def verify_email(token):
    user = fetch_user(token)
    if user:
        email, fullname, password, username, phone_number = user

        create_user(fullname, username, password, email, phone_number)
        delete_entry(email)

        return jsonify({'message': 'email verified and user created successfully'}), 201
    else:
        return jsonify({'message': 'Invalid or expired token'}), 400

    
@app.route('/user/signin', methods=['POST'])
def signin():
    data = request.json

    required_fields = ['username', 'password']
    missing_fields = [field for field in required_fields if field not in data or not data[field]]
    if missing_fields:
        return jsonify({'message': 'Missing fields', 'missing': missing_fields}), 400

    username = data['username']
    password = data['password']

    user_record = fetch_user_password_hash(username)
    if user_record and check_password_hash(user_record[0], password):
        # Generate token
        token = jwt.encode({'username': username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        redis_client.setex(token, 1800, username)
        return jsonify({'message': 'Login successful', 'token': token.decode('UTF-8')}), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/user/forgot_password', methods=['POST'])
def forgot_password():
    email = request.json.get('email')
    if not email:
        return jsonify({'message': 'Email is required'}), 400
    
    email_regex = r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'
    if not re.match(email_regex, email, re.IGNORECASE):
        return jsonify({"error": "Not a valid email format"}), 400
    
    user_id = fetch_user_id_by_email(email)
    if not user_id:
        return jsonify({'message': 'user not found'}), 404
    
    reset_token = secrets.token_hex(16)
    update_reset_token_for_user(user_id[0], reset_token)

    subject = 'Update your password'
    body = f"http://localhost:5000/user/reset_password/{reset_token}"
    recipient = email
    send_email(subject, recipient, body)

    return jsonify({'message': 'password reset link has been sent to your email'}), 200

@app.route('/user/reset_password/<token>')
def reset_password(token):
    if is_valid_reset_token(token):
        return render_template('reset_password.html', token=token)
    else:
        return jsonify({'message': 'Invalid or expired token'}), 400

@app.route('/user/update_password', methods=['POST'])
def update_password():
    token = request.form.get('token')
    new_password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')

    if not token or not new_password or not confirm_password:
        missing_fields = [field for field in ["token", "password", "confirm_password"] if not request.form.get(field)]
        return jsonify({'message': f'Missing field(s): {", ".join(missing_fields)}'}), 400

    if new_password != confirm_password:
        return jsonify({'message': 'Passwords do not match'}), 400

    hashed_password = generate_password_hash(new_password)
    if update_user_password(token, hashed_password):
        return jsonify({'message': 'password has been updated successfully'}), 200
    else:
        return jsonify({'message': 'Invalid or expired token'}), 400

@app.route('/user/upload_image', methods=['POST'])
@token_required
def upload_image(current_user):
    if not request.files:
        return jsonify({'message': 'No file found'}), 400

    file = next(request.files.values(), None)
    
    if not file or file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'message': 'jpg/jpeg/png formats are only supported'}), 400

    filename = secure_filename(file.filename)
    image_url = upload_to_azure_blob(file, filename)

    update_user_pic_url(current_user, image_url)

    return jsonify({'message': 'Image uploaded successfully', 'url': image_url}), 201

@app.route('/user/change_password', methods=['POST'])
@token_required
def change_password(current_user):
    old_password = request.json.get('old_password')
    new_password = request.json.get('new_password')
    confirm_password = request.json.get('confirm_password')

    if not all([old_password, new_password, confirm_password]):
        return jsonify({'message': 'All fields are required'}), 400

    if new_password != confirm_password:
        return jsonify({'message': 'Passwords do not match'}), 400

    if new_password == old_password:
        return jsonify({'message': 'Old and new passwords should not be the same'}), 400

    stored_hashed_password = get_user_password_hash(current_user)
    if stored_hashed_password and check_password_hash(stored_hashed_password, old_password):
        hashed_new_password = generate_password_hash(new_password)
        update_user_password(current_user, hashed_new_password)
        return jsonify({'message': 'Password has been changed successfully'}), 200
    else:
        return jsonify({'message': 'Incorrect old password'}), 400

if __name__ == "__main__":
    app.run(debug=True)