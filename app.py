from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-new'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hospital_v2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Make datetime available in all templates
@app.context_processor
def inject_datetime():
    return {'datetime': datetime}

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # patient, nurse, doctor, admin
    full_name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    phone = db.Column(db.String(15))

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    full_name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))
    phone = db.Column(db.String(15))
    email = db.Column(db.String(100))
    address = db.Column(db.Text)
    disease_taxonomy = db.Column(db.String(200))
    account_balance = db.Column(db.Float, default=0.0)
    family_patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=True)
    family_relation = db.Column(db.String(50))
    admission_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_registered = db.Column(db.Boolean, default=True)
    
    family_member = db.relationship('Patient', remote_side=[id], backref='related_patients')
    appointments = db.relationship('Appointment', backref='patient', lazy=True)

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    appointment_date = db.Column(db.DateTime, nullable=False)
    appointment_type = db.Column(db.String(50))
    reason = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')  # pending, approved, completed, cancelled
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    
    doctor = db.relationship('User', foreign_keys=[doctor_id], backref='doctor_appointments')
    approver = db.relationship('User', foreign_keys=[approved_by], backref='approved_appointments')

# Initialize database
with app.app_context():
    db.create_all()
    
    # Create default users if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            password=generate_password_hash('admin123'),
            role='admin',
            full_name='System Administrator',
            email='admin@hospital.com'
        )
        db.session.add(admin)
        print("[OK] Admin user created (admin/admin123)")
    
    if not User.query.filter_by(username='nurse1').first():
        nurse = User(
            username='nurse1',
            password=generate_password_hash('nurse123'),
            role='nurse',
            full_name='Sarah Johnson',
            email='nurse@hospital.com',
            phone='1234567890'
        )
        db.session.add(nurse)
        print("[OK] Nurse user created (nurse1/nurse123)")
    
    if not User.query.filter_by(username='doctor1').first():
        doctor = User(
            username='doctor1',
            password=generate_password_hash('doctor123'),
            role='doctor',
            full_name='Dr. John Smith',
            email='doctor@hospital.com',
            phone='0987654321'
        )
        db.session.add(doctor)
        print("[OK] Doctor user created (doctor1/doctor123)")
    
    if not User.query.filter_by(username='patient1').first():
        patient_user = User(
            username='patient1',
            password=generate_password_hash('patient123'),
            role='patient',
            full_name='John Doe',
            email='patient@example.com',
            phone='5555555555'
        )
        db.session.add(patient_user)
        db.session.commit()
        
        patient = Patient(
            user_id=patient_user.id,
            full_name='John Doe',
            age=30,
            gender='Male',
            phone='5555555555',
            email='patient@example.com',
            address='123 Main St',
            is_registered=True
        )
        db.session.add(patient)
        print("[OK] Patient user created (patient1/patient123)")
    
    db.session.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login/<role>', methods=['GET', 'POST'])
def login(role):
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username, role=role).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            session['full_name'] = user.full_name
            flash(f'Welcome {user.full_name}!', 'success')
            return redirect(url_for(f'{role}_dashboard'))
        else:
            flash('Invalid credentials!', 'danger')
    
    return render_template('login.html', role=role)

@app.route('/register/patient', methods=['GET', 'POST'])
def register_patient():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        age = request.form['age']
        gender = request.form['gender']
        phone = request.form['phone']
        email = request.form['email']
        address = request.form['address']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register_patient'))
        
        new_user = User(
            username=username,
            password=generate_password_hash(password),
            role='patient',
            full_name=full_name,
            email=email,
            phone=phone
        )
        db.session.add(new_user)
        db.session.commit()
        
        new_patient = Patient(
            user_id=new_user.id,
            full_name=full_name,
            age=age,
            gender=gender,
            phone=phone,
            email=email,
            address=address,
            is_registered=True
        )
        db.session.add(new_patient)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login', role='patient'))
    
    return render_template('register_patient.html')

@app.route('/patient/dashboard')
def patient_dashboard():
    if 'user_id' not in session or session['role'] != 'patient':
        flash('Please login first!', 'warning')
        return redirect(url_for('login', role='patient'))
    
    patient = Patient.query.filter_by(user_id=session['user_id']).first()
    if not patient:
        flash('Patient profile not found!', 'danger')
        return redirect(url_for('index'))
    
    appointments = Appointment.query.filter_by(patient_id=patient.id).order_by(Appointment.appointment_date.desc()).all()
    doctors = User.query.filter_by(role='doctor').all()
    return render_template('patient_dashboard.html', patient=patient, appointments=appointments, doctors=doctors)

@app.route('/patient/book_appointment', methods=['POST'])
def patient_book_appointment():
    if 'user_id' not in session or session['role'] != 'patient':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    patient = Patient.query.filter_by(user_id=session['user_id']).first()
    if not patient:
        return jsonify({'success': False, 'message': 'Patient profile not found'}), 404
    
    try:
        appointment_date_str = request.form['appointment_date']
        appointment_time_str = request.form['appointment_time']
        appointment_datetime = datetime.strptime(
            f"{appointment_date_str} {appointment_time_str}", 
            "%Y-%m-%d %H:%M"
        )
        
        doctor_id = request.form.get('doctor_id')
        if doctor_id and doctor_id != '':
            doctor_id = int(doctor_id)
        else:
            doctor_id = None
        
        new_appointment = Appointment(
            patient_id=patient.id,
            doctor_id=doctor_id,
            appointment_date=appointment_datetime,
            appointment_type=request.form['appointment_type'],
            reason=request.form['reason'],
            status='pending'
        )
        db.session.add(new_appointment)
        db.session.commit()
        
        flash('Appointment request submitted! Waiting for nurse approval.', 'success')
        return redirect(url_for('patient_dashboard'))
    except Exception as e:
        flash(f'Error booking appointment: {str(e)}', 'danger')
        return redirect(url_for('patient_dashboard'))

@app.route('/nurse/dashboard')
def nurse_dashboard():
    if 'user_id' not in session or session['role'] != 'nurse':
        flash('Please login first!', 'warning')
        return redirect(url_for('login', role='nurse'))
    
    patients = Patient.query.all()
    # Show pending and approved appointments
    appointments = Appointment.query.filter(
        Appointment.status.in_(['pending', 'approved'])
    ).order_by(Appointment.appointment_date).all()
    
    return render_template('nurse_dashboard.html', patients=patients, appointments=appointments)

@app.route('/nurse/approve_appointment/<int:appointment_id>', methods=['POST'])
def nurse_approve_appointment(appointment_id):
    if 'user_id' not in session or session['role'] != 'nurse':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('index'))
    
    appointment = Appointment.query.get_or_404(appointment_id)
    action = request.form.get('action')
    
    if action == 'approve':
        appointment.status = 'approved'
        appointment.approved_by = session['user_id']
        appointment.approved_at = datetime.utcnow()
        flash('Appointment approved successfully!', 'success')
    elif action == 'reject':
        appointment.status = 'cancelled'
        appointment.notes = request.form.get('notes', 'Rejected by nurse')
        flash('Appointment rejected!', 'info')
    
    db.session.commit()
    return redirect(url_for('nurse_dashboard'))

@app.route('/doctor/dashboard')
def doctor_dashboard():
    if 'user_id' not in session or session['role'] != 'doctor':
        flash('Please login first!', 'warning')
        return redirect(url_for('login', role='doctor'))
    
    # Show only approved appointments for this doctor
    appointments = Appointment.query.filter(
        Appointment.doctor_id == session['user_id'],
        Appointment.status == 'approved'
    ).order_by(Appointment.appointment_date).all()
    
    # Also show unassigned approved appointments
    unassigned_appointments = Appointment.query.filter(
        Appointment.doctor_id == None,
        Appointment.status == 'approved'
    ).order_by(Appointment.appointment_date).all()
    
    return render_template('doctor_dashboard.html', 
                         appointments=appointments, 
                         unassigned_appointments=unassigned_appointments)

@app.route('/doctor/complete_appointment/<int:appointment_id>', methods=['POST'])
def doctor_complete_appointment(appointment_id):
    if 'user_id' not in session or session['role'] != 'doctor':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('index'))
    
    appointment = Appointment.query.get_or_404(appointment_id)
    
    if appointment.doctor_id != session['user_id']:
        flash('You can only complete your own appointments!', 'danger')
        return redirect(url_for('doctor_dashboard'))
    
    appointment.status = 'completed'
    appointment.notes = request.form.get('notes', '')
    db.session.commit()
    
    flash('Appointment completed successfully!', 'success')
    return redirect(url_for('doctor_dashboard'))

@app.route('/doctor/claim_appointment/<int:appointment_id>', methods=['POST'])
def doctor_claim_appointment(appointment_id):
    if 'user_id' not in session or session['role'] != 'doctor':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('index'))
    
    appointment = Appointment.query.get_or_404(appointment_id)
    
    if appointment.doctor_id is not None:
        flash('This appointment is already assigned!', 'warning')
        return redirect(url_for('doctor_dashboard'))
    
    appointment.doctor_id = session['user_id']
    db.session.commit()
    
    flash('Appointment claimed successfully!', 'success')
    return redirect(url_for('doctor_dashboard'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Please login first!', 'warning')
        return redirect(url_for('login', role='admin'))
    
    patients = Patient.query.all()
    users = User.query.all()
    appointments = Appointment.query.order_by(Appointment.appointment_date.desc()).all()
    return render_template('admin_dashboard.html', patients=patients, users=users, appointments=appointments)

@app.route('/admin/register_staff', methods=['GET', 'POST'])
def register_staff():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        full_name = request.form['full_name']
        email = request.form['email']
        phone = request.form['phone']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return redirect(url_for('register_staff'))
        
        new_user = User(
            username=username,
            password=generate_password_hash(password),
            role=role,
            full_name=full_name,
            email=email,
            phone=phone
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'{role.capitalize()} registered successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('register_staff.html')

@app.route('/admin/delete_patient/<int:patient_id>', methods=['POST'])
def delete_patient(patient_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('index'))
    
    patient = Patient.query.get_or_404(patient_id)
    
    # Delete associated appointments first
    Appointment.query.filter_by(patient_id=patient_id).delete()
    
    # Delete associated user account if exists
    if patient.user_id:
        user = User.query.get(patient.user_id)
        if user:
            db.session.delete(user)
    
    # Delete the patient
    db.session.delete(patient)
    db.session.commit()
    
    flash('Patient deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Unauthorized access!', 'danger')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting admin accounts
    if user.role == 'admin':
        flash('Cannot delete admin accounts!', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    # If user is a patient, delete patient record too
    if user.role == 'patient':
        patient = Patient.query.filter_by(user_id=user_id).first()
        if patient:
            Appointment.query.filter_by(patient_id=patient.id).delete()
            db.session.delete(patient)
    
    # Delete appointments where user is doctor or approver
    Appointment.query.filter_by(doctor_id=user_id).update({'doctor_id': None})
    Appointment.query.filter_by(approved_by=user_id).update({'approved_by': None})
    
    db.session.delete(user)
    db.session.commit()
    
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)