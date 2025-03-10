from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, leave_room
import os
import random
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///videochat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")  # Вместо "eventlet"  
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    sent_friend_requests = db.relationship('Friendship', 
                                          foreign_keys='Friendship.user_id',
                                          backref='sender', 
                                          lazy='dynamic')
    received_friend_requests = db.relationship('Friendship', 
                                              foreign_keys='Friendship.friend_id',
                                              backref='receiver', 
                                              lazy='dynamic')
    
    sent_messages = db.relationship('Message',
                                   foreign_keys='Message.sender_id',
                                   backref='sender',
                                   lazy='dynamic')
    received_messages = db.relationship('Message',
                                      foreign_keys='Message.receiver_id',
                                      backref='receiver',
                                      lazy='dynamic')

class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        user_exists = User.query.filter_by(username=username).first()
        email_exists = User.query.filter_by(email=email).first()
        
        if user_exists:
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if email_exists:
            flash('Email already exists')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully!')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))
        
        login_user(user)
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get friends list
    friends = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) | (Friendship.friend_id == current_user.id)) &
        (Friendship.status == 'accepted')
    ).all()
    
    friend_users = []
    for friendship in friends:
        if friendship.user_id == current_user.id:
            friend_users.append(User.query.get(friendship.friend_id))
        else:
            friend_users.append(User.query.get(friendship.user_id))
    
    # Get pending friend requests
    pending_requests = Friendship.query.filter_by(
        friend_id=current_user.id, 
        status='pending'
    ).all()
    
    pending_users = [User.query.get(fr.user_id) for fr in pending_requests]
    
    # Get unread messages count
    unread_count = Message.query.filter_by(
        receiver_id=current_user.id,
        read=False
    ).count()
    
    return render_template('dashboard.html', 
                          friends=friend_users, 
                          pending_requests=pending_users,
                          unread_count=unread_count)

@app.route('/chat-roulette')
@login_required
def chat_roulette():
    return render_template('chat_roulette.html')

@app.route('/friends')
@login_required
def friends():
    # Get friends list
    friends = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) | (Friendship.friend_id == current_user.id)) &
        (Friendship.status == 'accepted')
    ).all()
    
    friend_users = []
    for friendship in friends:
        if friendship.user_id == current_user.id:
            friend_users.append(User.query.get(friendship.friend_id))
        else:
            friend_users.append(User.query.get(friendship.user_id))
    
    # Get pending friend requests
    pending_requests = Friendship.query.filter_by(
        friend_id=current_user.id, 
        status='pending'
    ).all()
    
    pending_users = [User.query.get(fr.user_id) for fr in pending_requests]
    
    # Get sent friend requests
    sent_requests = Friendship.query.filter_by(
        user_id=current_user.id, 
        status='pending'
    ).all()
    
    sent_users = [User.query.get(fr.friend_id) for fr in sent_requests]
    
    return render_template('friends.html', 
                          friends=friend_users, 
                          pending_requests=pending_users,
                          sent_requests=sent_users)

@app.route('/add-friend', methods=['POST'])
@login_required
def add_friend():
    username = request.form.get('username')
    
    if not username:
        flash('Please enter a username')
        return redirect(url_for('friends'))
    
    user = User.query.filter_by(username=username).first()
    
    if not user:
        flash('User not found')
        return redirect(url_for('friends'))
    
    if user.id == current_user.id:
        flash('You cannot add yourself as a friend')
        return redirect(url_for('friends'))
    
    # Check if friendship already exists
    existing = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == user.id)) |
        ((Friendship.user_id == user.id) & (Friendship.friend_id == current_user.id))
    ).first()
    
    if existing:
        flash('Friend request already exists or you are already friends')
        return redirect(url_for('friends'))
    
    new_friendship = Friendship(user_id=current_user.id, friend_id=user.id)
    db.session.add(new_friendship)
    db.session.commit()
    
    flash(f'Friend request sent to {user.username}')
    return redirect(url_for('friends'))

@app.route('/accept-friend/<int:request_id>')
@login_required
def accept_friend(request_id):
    friendship = Friendship.query.get_or_404(request_id)
    
    if friendship.friend_id != current_user.id:
        flash('Unauthorized action')
        return redirect(url_for('friends'))
    
    friendship.status = 'accepted'
    db.session.commit()
    
    flash('Friend request accepted')
    return redirect(url_for('friends'))

@app.route('/reject-friend/<int:request_id>')
@login_required
def reject_friend(request_id):
    friendship = Friendship.query.get_or_404(request_id)
    
    if friendship.friend_id != current_user.id:
        flash('Unauthorized action')
        return redirect(url_for('friends'))
    
    friendship.status = 'rejected'
    db.session.commit()
    
    flash('Friend request rejected')
    return redirect(url_for('friends'))

@app.route('/messages')
@login_required
def messages():
    friends = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) | (Friendship.friend_id == current_user.id)) &
        (Friendship.status == 'accepted')
    ).all()
    
    friend_users = []
    for friendship in friends:
        if friendship.user_id == current_user.id:
            friend_users.append(User.query.get(friendship.friend_id))
        else:
            friend_users.append(User.query.get(friendship.user_id))
    
    return render_template('messages.html', friends=friend_users)

@app.route('/messages/<int:user_id>')
@login_required
def chat(user_id):
    friend = User.query.get_or_404(user_id)
    
    # Check if they are friends
    friendship = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == friend.id)) |
        ((Friendship.user_id == friend.id) & (Friendship.friend_id == current_user.id))
    ).first()
    
    if not friendship or friendship.status != 'accepted':
        flash('You are not friends with this user')
        return redirect(url_for('messages'))
    
    # Get messages between the two users
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == friend.id)) |
        ((Message.sender_id == friend.id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.created_at).all()
    
    # Mark unread messages as read
    unread_messages = Message.query.filter_by(
        sender_id=friend.id,
        receiver_id=current_user.id,
        read=False
    ).all()
    
    for msg in unread_messages:
        msg.read = True
    
    db.session.commit()
    
    return render_template('chat.html', friend=friend, messages=messages)

@app.route('/send-message', methods=['POST'])
@login_required
def send_message():
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('content')
    
    if not receiver_id or not content:
        return jsonify({'error': 'Missing data'}), 400
    
    receiver = User.query.get(receiver_id)
    if not receiver:
        return jsonify({'error': 'User not found'}), 404
    
    # Check if they are friends
    friendship = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == receiver.id)) |
        ((Friendship.user_id == receiver.id) & (Friendship.friend_id == current_user.id))
    ).first()
    
    if not friendship or friendship.status != 'accepted':
        return jsonify({'error': 'You are not friends with this user'}), 403
    
    new_message = Message(
        sender_id=current_user.id,
        receiver_id=receiver.id,
        content=content
    )
    
    db.session.add(new_message)
    db.session.commit()
    
    # Emit socket event
    socketio.emit('new_message', {
        'sender_id': current_user.id,
        'receiver_id': receiver.id,
        'content': content,
        'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    }, room=f'user_{receiver.id}')
    
    return jsonify({
        'success': True,
        'message': {
            'id': new_message.id,
            'content': new_message.content,
            'timestamp': new_message.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
    })

@app.route('/add-friend-during-chat/<int:user_id>')
@login_required
def add_friend_during_chat(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        return jsonify({'error': 'You cannot add yourself as a friend'}), 400
    
    # Check if friendship already exists
    existing = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == user.id)) |
        ((Friendship.user_id == user.id) & (Friendship.friend_id == current_user.id))
    ).first()
    
    if existing:
        return jsonify({'error': 'Friend request already exists or you are already friends'}), 400
    
    new_friendship = Friendship(user_id=current_user.id, friend_id=user.id)
    db.session.add(new_friendship)
    db.session.commit()
    
    return jsonify({'success': True, 'message': f'Friend request sent to {user.username}'})

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        join_room(f'user_{current_user.id}')

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        leave_room(f'user_{current_user.id}')

@socketio.on('join_roulette')
def handle_join_roulette():
    session['in_roulette'] = True
    # Add to waiting pool
    waiting_users = session.get('waiting_users', [])
    if current_user.id not in waiting_users:
        waiting_users.append(current_user.id)
    session['waiting_users'] = waiting_users
    
    # Try to match with another user
    if len(waiting_users) >= 2:
        user1_id = waiting_users.pop(0)
        user2_id = waiting_users.pop(0)
        
        # Update waiting users
        session['waiting_users'] = waiting_users
        
        # Create a unique room for these two users
        room_id = f'chat_{min(user1_id, user2_id)}_{max(user1_id, user2_id)}'
        
        # Notify both users about the match
        emit('match_found', {
            'room_id': room_id,
            'peer_id': user2_id,
            'peer_username': User.query.get(user2_id).username
        }, room=f'user_{user1_id}')
        
        emit('match_found', {
            'room_id': room_id,
            'peer_id': user1_id,
            'peer_username': User.query.get(user1_id).username
        }, room=f'user_{user2_id}')

@socketio.on('leave_roulette')
def handle_leave_roulette():
    session['in_roulette'] = False
    # Remove from waiting pool
    waiting_users = session.get('waiting_users', [])
    if current_user.id in waiting_users:
        waiting_users.remove(current_user.id)
    session['waiting_users'] = waiting_users

@socketio.on('join_room')
def handle_join_room(data):
    room_id = data['room_id']
    join_room(room_id)

@socketio.on('leave_room')
def handle_leave_room(data):
    room_id = data['room_id']
    leave_room(room_id)

@socketio.on('signal')
def handle_signal(data):
    room_id = data['room_id']
    emit('signal', {
        'user_id': current_user.id,
        'signal_data': data['signal_data']
    }, room=room_id, include_self=False)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port, debug=True, allow_unsafe_werkzeug=True)




