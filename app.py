from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Blueprint
from flask_socketio import SocketIO, join_room, leave_room, emit
from sqlalchemy import or_, and_

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for session
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rentease.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
socketio = SocketIO(app)

class User(db.Model):
    __tablename__ = 'tbl_users'
    id = db.Column('User_Id', db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    contact = db.Column(db.String(255))
    role = db.Column(db.String(50), nullable=False)  # 'tenant' or 'landlord'
    verified = db.Column(db.Boolean, default=False)
    verification_requested = db.Column(db.Boolean, default=False)
    properties = db.relationship('Property', backref='owner', lazy=True)

class Property(db.Model):
    __tablename__ = 'tbl_property'
    id = db.Column('property_id', db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('tbl_users.User_Id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255))
    address = db.Column(db.String(255))
    price = db.Column(db.String(255))
    type = db.Column(db.String(50))  # ENUM: Apartment, House, Condo, etc.
    status = db.Column(db.String(50))  # ENUM: Available, Rented, etc.
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    verified = db.Column(db.Boolean, default=False)
    location = db.relationship('Location', uselist=False, backref='property')
    images = db.relationship('Image', backref='property', lazy=True)

class Location(db.Model):
    __tablename__ = 'tbl_location'
    id = db.Column('location_id', db.Integer, primary_key=True)
    property_id = db.Column(db.Integer, db.ForeignKey('tbl_property.property_id'), nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    city = db.Column(db.String(255))
    province = db.Column(db.String(255))

class Image(db.Model):
    __tablename__ = 'tbl_image'
    id = db.Column('image_id', db.Integer, primary_key=True)
    property_id = db.Column(db.Integer, db.ForeignKey('tbl_property.property_id'), nullable=False)
    image_file = db.Column(db.String(255), nullable=False)

class AdminAction(db.Model):
    __tablename__ = 'tbl_adminaction'
    id = db.Column('action_id', db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('tbl_users.User_Id'), nullable=False)
    property_id = db.Column(db.Integer, db.ForeignKey('tbl_property.property_id'), nullable=False)
    action = db.Column(db.String(50))
    date = db.Column(db.DateTime, default=datetime.utcnow)

class Review(db.Model):
    __tablename__ = 'tbl_review'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('tbl_users.User_Id'), nullable=False)
    property_id = db.Column(db.Integer, db.ForeignKey('tbl_property.property_id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String(500))
    date = db.Column(db.DateTime, default=datetime.utcnow)

# Rename Message model to UserMessage to avoid conflict with Flask-Mail's Message
class UserMessage(db.Model):
    __tablename__ = 'tbl_message'
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('tbl_users.User_Id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('tbl_users.User_Id'), nullable=False)
    content = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


@app.route('/')
def index():
    return redirect(url_for('login'))  # Default page is login

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if not user:
            error = 'Email does not exist. Please register first.'
        elif not check_password_hash(user.password, password):
            error = 'Invalid password.'
        else:
            session['user_id'] = user.id
            session['role'] = user.role
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'landlord':
                return redirect(url_for('landlord_dashboard'))
            else:
                return redirect(url_for('home'))
        flash(error, 'danger')
    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        user_type = request.form.get('user_type', 'tenant')
        contact = request.form.get('contact')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered.', 'danger')
            return render_template('auth/register.html')
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/register.html')
        if user_type not in ['tenant', 'landlord']:
            flash('Invalid user type.', 'danger')
            return render_template('auth/register.html')

        hashed_password = generate_password_hash(password)
        new_user = User(name=name, email=email, password=hashed_password, contact=contact, role=user_type)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/register.html')

@app.route('/home')
def home():
    return render_template('pages/home.html')

@app.route('/listings')
def listings():
    if 'user_id' not in session:
        flash('Please log in.', 'danger')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user.verified:
        flash('You must be verified to browse listings.', 'warning')
        return redirect(url_for('profile'))
    listings = Property.query.filter_by(verified=True).all()
    return render_template('pages/listings.html', listings=listings, user=user)

@app.route('/rental/<int:rental_id>')
def rental_detail(rental_id):
    property = Property.query.get_or_404(rental_id)
    landlord = User.query.get(property.user_id)
    return render_template('pages/rental_detail.html', rental_id=rental_id, property=property, landlord=landlord)

@app.route('/messages')
def messages():
    if 'user_id' not in session:
        flash('Please log in.', 'danger')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    # Get all users this user has messaged or received messages from
    user_id = session['user_id']
    # Find all unique user ids in conversations
    sent = db.session.query(UserMessage.receiver_id).filter_by(sender_id=user_id)
    received = db.session.query(UserMessage.sender_id).filter_by(receiver_id=user_id)
    user_ids = set([uid for (uid,) in sent] + [uid for (uid,) in received])
    user_ids.discard(user_id)
    conversations = User.query.filter(User.id.in_(user_ids)).all() if user_ids else []
    # Get selected conversation
    other_id = request.args.get('user')
    messages_history = []
    other_user = None
    if other_id:
        other_user = User.query.get(int(other_id))
        messages_history = UserMessage.query.filter(
            or_(and_(UserMessage.sender_id==user_id, UserMessage.receiver_id==other_id),
                 and_(UserMessage.sender_id==other_id, UserMessage.receiver_id==user_id))
        ).order_by(UserMessage.timestamp.asc()).all()
    return render_template('pages/messages.html', user=user, conversations=conversations, messages_history=messages_history, other_user=other_user)

@app.route('/reviews')
def reviews():
    return render_template('pages/reviews.html')

@app.route('/landlord/dashboard')
def landlord_dashboard():
    if 'role' not in session or session['role'] != 'landlord':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    user = User.query.get(session['user_id'])
    properties = Property.query.filter_by(user_id=session['user_id']).all()
    return render_template('pages/landlord_dashboard.html', properties=properties, user=user)

@app.route('/landlord/delete/<int:property_id>', methods=['POST'])
def delete_listing(property_id):
    if 'role' not in session or session['role'] != 'landlord':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    property = Property.query.get_or_404(property_id)
    if property.user_id != session['user_id']:
        flash('You do not have permission to delete this listing.', 'danger')
        return redirect(url_for('landlord_dashboard'))
    db.session.delete(property)
    db.session.commit()
    flash('Listing deleted successfully!', 'info')
    return redirect(url_for('landlord_dashboard'))

@app.route('/landlord/add', methods=['GET', 'POST'])
def add_listing():
    # Only allow landlords
    if 'role' not in session or session['role'] != 'landlord':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    user = User.query.get(session['user_id'])
    if not user.verified:
        return render_template('pages/add_listing.html', user=user)
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        price = request.form.get('price')
        address = request.form.get('address')
        type_ = request.form.get('type')
        user_id = session['user_id']
        new_property = Property(
            title=title,
            description=description,
            price=price,
            address=address,
            type=type_,
            user_id=user_id,
            status='Available',
            verified=False
        )
        db.session.add(new_property)
        db.session.commit()
        flash('Listing added successfully! Awaiting admin verification.', 'success')
        return redirect(url_for('landlord_dashboard'))
    return render_template('pages/add_listing.html', user=user)

@app.route('/landlord/edit/<int:property_id>', methods=['GET', 'POST'])
def landlord_edit(property_id):
    # Only allow landlords
    if 'role' not in session or session['role'] != 'landlord':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))
    property = Property.query.get_or_404(property_id)
    if property.user_id != session['user_id']:
        flash('You do not have permission to edit this listing.', 'danger')
        return redirect(url_for('landlord_dashboard'))
    if request.method == 'POST':
        property.title = request.form.get('title')
        property.description = request.form.get('description')
        property.price = request.form.get('price')
        property.address = request.form.get('address')
        property.type = request.form.get('type')
        property.status = request.form.get('status')
        db.session.commit()
        flash('Listing updated successfully!', 'success')
        return redirect(url_for('landlord_dashboard'))
    return render_template('pages/landlord_edit.html', property=property)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please log in.', 'danger')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('pages/profile.html', user=user)

@app.route('/request_verification', methods=['POST'])
def request_verification():
    if 'user_id' not in session:
        flash('Please log in.', 'danger')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user.verified and not user.verification_requested:
        user.verification_requested = True
        db.session.commit()
        flash('Verification request sent. Please wait for admin approval.', 'info')
    return redirect(url_for('profile'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- Admin Routes ---

@app.route('/admin')
def admin_dashboard():
    pending_listings_count = Property.query.filter_by(status='Pending').count()
    users_count = User.query.count()
    rental_requests_count = 0  # Placeholder, implement if rental requests model exists
    flagged_listings_count = Property.query.filter_by(status='Flagged').count()
    recent_activity = []  # Placeholder, implement admin activity log if needed
    return render_template('pages/admin_dashboard.html',
        pending_listings_count=pending_listings_count,
        users_count=users_count,
        rental_requests_count=rental_requests_count,
        flagged_listings_count=flagged_listings_count,
        recent_activity=recent_activity)

@app.route('/admin/listings')
def admin_listings():
    listings = Property.query.all()
    return render_template('pages/admin_listings.html', listings=listings)

@app.route('/admin/listings/verify/<int:listing_id>', methods=['POST'])
def admin_verify_listing(listing_id):
    listing = Property.query.get_or_404(listing_id)
    listing.status = 'Verified'
    db.session.commit()
    flash('Listing verified successfully.', 'success')
    return redirect(url_for('admin_listings'))

@app.route('/admin/listings/reject/<int:listing_id>', methods=['POST'])
def admin_reject_listing(listing_id):
    listing = Property.query.get_or_404(listing_id)
    listing.status = 'Rejected'
    db.session.commit()
    flash('Listing rejected.', 'danger')
    return redirect(url_for('admin_listings'))

@app.route('/admin/listings/edit/<int:listing_id>', methods=['GET', 'POST'])
def admin_edit_listing(listing_id):
    listing = Property.query.get_or_404(listing_id)
    if request.method == 'POST':
        listing.title = request.form['title']
        listing.description = request.form['description']
        listing.address = request.form['address']
        listing.price = request.form['price']
        listing.type = request.form['type']
        db.session.commit()
        flash('Listing updated.', 'success')
        return redirect(url_for('admin_listings'))
    return render_template('pages/admin_edit_listing.html', listing=listing)

@app.route('/admin/listings/delete/<int:listing_id>', methods=['POST'])
def admin_delete_listing(listing_id):
    listing = Property.query.get_or_404(listing_id)
    db.session.delete(listing)
    db.session.commit()
    flash('Listing deleted.', 'info')
    return redirect(url_for('admin_listings'))

@app.route('/admin/users')
def admin_users():
    users = User.query.all()
    return render_template('pages/admin_users.html', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
def admin_edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.name = request.form['name']
        user.email = request.form['email']
        user.contact = request.form['contact']
        user.role = request.form['role']
        db.session.commit()
        flash('User updated.', 'success')
        return redirect(url_for('admin_users'))
    return render_template('pages/admin_edit_user.html', user=user)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted.', 'info')
    return redirect(url_for('admin_users'))

# Rental requests management placeholder (implement if model exists)
@app.route('/admin/requests')
def admin_requests():
    requests = []  # Replace with actual query if rental requests model exists
    return render_template('pages/admin_requests.html', requests=requests)

@app.route('/admin/requests/approve/<int:request_id>', methods=['POST'])
def admin_approve_request(request_id):
    # Implement logic if rental requests model exists
    flash('Rental request approved.', 'success')
    return redirect(url_for('admin_requests'))

@app.route('/admin/requests/reject/<int:request_id>', methods=['POST'])
def admin_reject_request(request_id):
    # Implement logic if rental requests model exists
    flash('Rental request rejected.', 'danger')
    return redirect(url_for('admin_requests'))

@app.route('/admin/requests/view/<int:request_id>')
def admin_view_request(request_id):
    # Implement logic if rental requests model exists
    request_obj = None
    return render_template('pages/admin_view_request.html', request=request_obj)

@app.route('/admin/verify_users', methods=['GET', 'POST'])
def admin_verify_users():
    if 'role' not in session or session['role'] != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        user_id = int(request.form.get('user_id'))
        action = request.form.get('action')
        user = User.query.get(user_id)
        if user:
            if action == 'approve':
                user.verified = True
                user.verification_requested = False
                db.session.commit()
                flash(f'User {user.name} verified.', 'success')
            elif action == 'reject':
                user.verification_requested = False
                db.session.commit()
                flash(f'User {user.name} verification rejected.', 'info')
    pending_users = User.query.filter_by(verification_requested=True).all()
    return render_template('pages/admin_verify_users.html', pending_users=pending_users)

@app.route('/admin/verify_listings', methods=['GET', 'POST'])
def admin_verify_listings():
    if 'role' not in session or session['role'] != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        property_id = int(request.form.get('property_id'))
        action = request.form.get('action')
        prop = Property.query.get(property_id)
        if prop:
            if action == 'approve':
                prop.verified = True
                db.session.commit()
                flash(f'Listing {prop.title} verified.', 'success')
            elif action == 'reject':
                db.session.delete(prop)
                db.session.commit()
                flash(f'Listing {prop.title} rejected and deleted.', 'info')
    pending_listings = Property.query.filter_by(verified=False).all()
    return render_template('pages/admin_verify_listings.html', pending_listings=pending_listings)

# --- SocketIO Events for Real-Time Messaging ---
@socketio.on('join_room')
def handle_join_room(data):
    room = data['room']
    join_room(room)

@socketio.on('leave_room')
def handle_leave_room(data):
    room = data['room']
    leave_room(room)

@socketio.on('send_message')
def handle_send_message(data):
    sender_id = data['sender_id']
    receiver_id = data['receiver_id']
    content = data['content']
    room = data['room']
    # Save message to DB
    msg = UserMessage(sender_id=sender_id, receiver_id=receiver_id, content=content)
    db.session.add(msg)
    db.session.commit()
    emit('receive_message', {
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'content': content,
        'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    }, room=room)

# --- Ensure admin role is supported in User model (already present as 'role' field) ---

# --- Add a route to create a default admin user if not exists ---

# Call this function on app startup
with app.app_context():
    # Create all database tables
    db.create_all()
    # Insert static admin user if not exists
    from sqlalchemy import exists
    if not db.session.query(exists().where(User.email == 'admin@rentease.com')).scalar():
        admin = User(
            name='Admin',
            email='admin@rentease.com',
            password=generate_password_hash('admin321'),
            contact='0000000000',
            role='admin'
        )
        db.session.add(admin)
        db.session.commit()


if __name__ == '__main__':
    socketio.run(app, debug=True)

