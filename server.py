import eventlet
eventlet.monkey_patch()
import eventlet.wsgi

import os
import base64
import time
from flask import Flask, request, jsonify, send_from_directory,render_template
from flask_socketio import SocketIO, emit
from flask_mail import Mail, Message
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from datetime import datetime, timedelta
from bson import ObjectId
from flask_cors import CORS
from dotenv import load_dotenv
load_dotenv()


# === Flask App Setup ===
app = Flask(__name__)
CORS(app) 
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['MONGO_URI'] = os.environ.get('MONGO_URI')
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ['true', '1']
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')


mongo = PyMongo(app)
mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*")

connected_cams = {}  # camId -> sid

# === Auth Decorator ===
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = mongo.db.users.find_one({'email': data['email']})
        except:
            return jsonify({'message': 'Invalid token'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# === Routes ===
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if mongo.db.users.find_one({'email': data['email']}):
        return jsonify({'message': 'Email already registered'}), 400

    hashed_pw = generate_password_hash(data['password'])
    mongo.db.users.insert_one({
        'name': data['name'],
        'email': data['email'],
        'password_hash': hashed_pw,
        'cams': []
    })

    return jsonify({'message': 'Registered successfully'})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = mongo.db.users.find_one({'email': data['email']})
    if user and check_password_hash(user['password_hash'], data['password']):
        token = jwt.encode({'email': user['email'], 'exp': datetime.utcnow() + timedelta(hours=24)}, app.config['SECRET_KEY'])
        return jsonify({'token': token})
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/createCam', methods=['POST'])
@token_required
def create_cam(current_user):
    data = request.json
    cam_id = str(int(time.time()*1000))[-6:]  # Unique cam ID
    cam_obj = { 'camId': cam_id, 'recipient': data['recipient'] }
    mongo.db.users.update_one({'email': current_user['email']}, {'$push': {'cams': cam_obj}})
    return jsonify({'message': 'Cam created', 'camId': cam_id})

@app.route('/capture/<camId>')
def trigger_capture(camId):
    socketio.emit(f'capture_{camId}', {'message': 'capture'})
    return jsonify({'message': f'Capture signal sent to {camId}'})

@app.route('/my_cams')
@token_required
def my_cams(current_user):
    return jsonify(current_user['cams'])

@app.route('/edit_cam/<camId>', methods=['PUT'])
@token_required
def edit_cam(current_user, camId):
    new_email = request.json['recipient']
    mongo.db.users.update_one(
        {'email': current_user['email'], 'cams.camId': camId},
        {'$set': {'cams.$.recipient': new_email}}
    )
    return jsonify({'message': 'Recipient updated'})

@app.route('/delete_cam/<camId>', methods=['DELETE'])
@token_required
def delete_cam(current_user, camId):
    # Verify that camId belongs to current user
    user_cams = current_user.get('cams', [])
    if not any(cam['camId'] == camId for cam in user_cams):
        return jsonify({'message': 'Unauthorized or invalid camId'}), 403

    # Remove cam from user document
    mongo.db.users.update_one(
        {'email': current_user['email']},
        {'$pull': {'cams': {'camId': camId}}}
    )

    # Optionally delete all images associated with this camId
    mongo.db.images.delete_many({'camId': camId})

    # Remove from connected WebSocket cams if connected
    if camId in connected_cams:
        del connected_cams[camId]

    return jsonify({'message': f'Camera {camId} and its images deleted successfully'})

@app.route('/images/<camId>')
def list_images(camId):
    # Fetch images for the given camId
    imgs = mongo.db.images.find({'camId': camId})
    images = [{'image': img['image'], 'timestamp': img['timestamp']} for img in imgs]

    return render_template('images.html', camId=camId, images=images)


@app.route('/api/images/<camId>', methods=['GET'])
@token_required
def api_images(current_user, camId):
    # Optional: ensure user owns this camId
    user_cam_ids = [cam['camId'] for cam in current_user.get('cams', [])]
    if camId not in user_cam_ids:
        return jsonify({"message": "Unauthorized access to this camera"}), 403

    imgs = mongo.db.images.find({'camId': camId})
    image_list = [{'timestamp': img['timestamp'], 'image': img['image']} for img in imgs]
    return jsonify({'camId': camId, 'images': image_list})

@app.route('/delete_images/<camId>', methods=['DELETE'])
@token_required
def delete_images(current_user, camId):
    # Validate camId belongs to current user
    cam_ids = [cam['camId'] for cam in current_user.get('cams', [])]
    if camId not in cam_ids:
        return jsonify({'message': 'Unauthorized or invalid camId'}), 403

    # Optional parameter: number of recent images to delete
    limit = request.args.get('last', type=int)

    if limit:
        # Get last N image ObjectIds for camId sorted by insertion (assuming default _id order)
        images = mongo.db.images.find({'camId': camId}).sort([('_id', -1)]).limit(limit)
        ids_to_delete = [img['_id'] for img in images]

        if not ids_to_delete:
            return jsonify({'message': 'No images found to delete'}), 404

        result = mongo.db.images.delete_many({'_id': {'$in': ids_to_delete}})
        return jsonify({'message': f'Deleted last {result.deleted_count} image(s) for camId {camId}.'})
    else:
        result = mongo.db.images.delete_many({'camId': camId})
        return jsonify({'message': f'Deleted all ({result.deleted_count}) image(s) for camId {camId}.'})

@app.route('/<path:filename>')
def serve_root_file(filename):
    return send_from_directory(os.getcwd(), filename)

    
# Catch-all route to support React Router
@app.route('/')
def index():
    return render_template("index.html")
    
# === WebSocket Handler ===
@socketio.on('connect')
def on_connect():
    print(f"[WS] Client connected: {request.sid}")

@socketio.on('register_cam')
def register_cam(data):
    cam_id = data.get('camId')
    if not cam_id:
        emit('error', {'message': 'camId required'})
        return

    if cam_id in connected_cams:
        emit('error', {'message': 'camId already in use'})
        return

    connected_cams[cam_id] = request.sid
    print(f"[WS] Registered camId {cam_id} with sid {request.sid}")
    emit('registered', {'message': f'camId {cam_id} registered'})

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    for cam_id, stored_sid in list(connected_cams.items()):
        if stored_sid == sid:
            print(f"[WS] CamId {cam_id} disconnected")
            del connected_cams[cam_id]

@socketio.on('image_data')
def on_image_data(data):
    cam_id = data.get('camId')
    image_data = data.get('image')
    if image_data.startswith("data:image"):
        image_data = image_data.split(',')[1]

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    mongo.db.images.insert_one({
        'camId': cam_id,
        'timestamp': timestamp,
        'image': image_data
    })

    user = mongo.db.users.find_one({'cams.camId': cam_id})
    if user:
        recipient = next((c['recipient'] for c in user['cams'] if c['camId'] == cam_id), None)
        if recipient:
            msg = Message(subject="🚨 Motion Detected!", sender=app.config['MAIL_USERNAME'], recipients=[recipient], body=f"Motion detected at {timestamp}")
            msg.attach("image.jpg", "image/jpeg", base64.b64decode(image_data))
            try:
                mail.send(msg)
                print(f"[EMAIL] Sent to {recipient}")
            except Exception as e:
                print(f"[EMAIL ERROR] {e}")

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)

