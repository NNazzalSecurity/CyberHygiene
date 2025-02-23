from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import numpy as np
import random
import string
from datetime import datetime
import re
import pandas as pd
import json
import uuid
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
from flask import send_file
from flask_migrate import Migrate

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cyberhygiene.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    sector = db.Column(db.String(50))
    score = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    badges = db.relationship('Badge', backref='user', lazy=True)
    certifications = db.relationship('Certification', backref='user', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Badge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    icon = db.Column(db.String(50))
    color = db.Column(db.String(50))
    earned_date = db.Column(db.DateTime, default=datetime.utcnow)

class Certification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500))
    icon = db.Column(db.String(50))
    color = db.Column(db.String(50))
    progress = db.Column(db.Integer, default=0)  # Progress percentage
    issued_date = db.Column(db.DateTime)
    pdf_path = db.Column(db.String(200))  # Path to stored certificate PDF

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Delete the old database file and create new one
with app.app_context():
    try:
        os.remove('cyberhygiene.db')
    except:
        pass
    
    # Create all tables
    db.create_all()
    
    # Create a test user if none exists
    if not User.query.filter_by(username='test').first():
        test_user = User(
            username='test',
            email='test@example.com',
            password_hash=generate_password_hash('test'),
            sector='personal',
            score=0
        )
        db.session.add(test_user)
        db.session.commit()

# Download required NLTK data
try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt')

try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords')

try:
    nltk.data.find('taggers/averaged_perceptron_tagger')
except LookupError:
    nltk.download('averaged_perceptron_tagger')

# Load the CEAS dataset
def load_ceas_dataset():
    try:
        print("Attempting to load CEAS dataset...")
        df = pd.read_csv('CEAS_08.csv')
        print(f"Dataset loaded with {len(df)} rows")
        return df
    except Exception as e:
        print(f"Error loading CEAS dataset: {str(e)}")
        # Create a fallback dataset
        return pd.DataFrame({
            'sender': ['security@google.com-secure-alert.net', 'statements@chase.com'],
            'subject': ['Security Alert: Sign-in from new device', 'Your Monthly Statement is Ready'],
            'body': ['We detected a sign-in attempt from an unrecognized device. If this wasn\'t you, click here to secure your account: [Link]',
                    'Your monthly account statement is now available in your online banking portal. Please log in to your account through our secure website to view it.'],
            'label': [1, 0]  # 1 for phishing, 0 for legitimate
        })

# Initialize the dataset
ceas_df = None
with app.app_context():
    db.create_all()
    ceas_df = load_ceas_dataset()

# Incident Response Scenarios
incident_scenarios = {
    'malware': [
        {
            'id': 'malware_1',
            'title': 'Suspicious Process Detection',
            'description': 'System monitoring has detected an unknown process consuming high CPU and making unusual network connections.',
            'severity': 'High',
            'indicators': [
                'High CPU Usage',
                'Unknown Network Connections',
                'Modified System Files'
            ],
            'steps': [
                {
                    'question': 'What should be your first action?',
                    'options': [
                        'Immediately shut down the system',
                        'Identify and document the suspicious process',
                        'Delete all unknown processes',
                        'Ignore it as it might be a system update'
                    ],
                    'correct': 1,
                    'explanation': 'First identify and document the suspicious process. This helps in understanding the scope of the potential infection and provides valuable information for analysis.'
                },
                {
                    'question': 'The process is confirmed suspicious. What next?',
                    'options': [
                        'Isolate the affected system from the network',
                        'Try to kill the process',
                        'Run a quick antivirus scan',
                        'Restart the computer'
                    ],
                    'correct': 0,
                    'explanation': 'Isolating the system prevents the potential malware from spreading to other systems on the network.'
                },
                {
                    'question': 'How should you analyze the situation?',
                    'options': [
                        'Only check current running processes',
                        'Review system and network logs',
                        'Just run antivirus',
                        'Ask the user what happened'
                    ],
                    'correct': 1,
                    'explanation': 'A thorough review of system and network logs helps understand the timeline and scope of the incident.'
                }
            ]
        }
    ],
    'phishing': [
        {
            'id': 'phishing_1',
            'title': 'Suspicious Email Report',
            'description': 'An employee reports receiving an email asking to verify their account credentials due to suspicious activity.',
            'severity': 'Medium',
            'indicators': [
                'Urgent Account Verification Request',
                'External Email Domain',
                'Generic Greeting'
            ],
            'steps': [
                {
                    'question': 'What should you do first?',
                    'options': [
                        'Delete the email immediately',
                        'Click the link to check if it\'s legitimate',
                        'Forward the email to all employees as a warning',
                        'Preserve the email and document its details'
                    ],
                    'correct': 3,
                    'explanation': 'Preserve evidence and document details for proper investigation and future reference.'
                },
                {
                    'question': 'What immediate action should be taken?',
                    'options': [
                        'Reset the employee\'s password',
                        'Block the sender\'s domain',
                        'Check if others received similar emails',
                        'Report to external authorities'
                    ],
                    'correct': 2,
                    'explanation': 'Check if other employees received similar emails to understand the scope of the potential phishing campaign.'
                }
            ]
        }
    ],
    'data_breach': [
        {
            'id': 'breach_1',
            'title': 'Unauthorized Data Access',
            'description': 'Database monitoring alerts show unusual query patterns and large data transfers during off-hours.',
            'severity': 'Critical',
            'indicators': [
                'Unusual Query Patterns',
                'Large Data Transfers',
                'Off-hours Activity'
            ],
            'steps': [
                {
                    'question': 'What is the first step to take?',
                    'options': [
                        'Shut down the database immediately',
                        'Monitor and log all current activity',
                        'Delete the affected database',
                        'Ignore it as it might be a false alarm'
                    ],
                    'correct': 1,
                    'explanation': 'Start by monitoring and logging all activity to gather evidence while maintaining service.'
                },
                {
                    'question': 'How should you contain the incident?',
                    'options': [
                        'Block all database access',
                        'Block suspicious IP addresses and audit access logs',
                        'Delete the affected database',
                        'Ignore it as it might be a false alarm'
                    ],
                    'correct': 1,
                    'explanation': 'Blocking suspicious IPs and auditing logs helps contain the incident while maintaining legitimate access.'
                }
            ]
        }
    ]
}

# Sector-specific training configuration
SECTOR_CONFIG = {
    'healthcare': {
        'name': 'Healthcare',
        'icon': 'fa-hospital',
        'class': 'text-danger',
        'description': 'Specialized cybersecurity training for healthcare professionals, focusing on patient data protection and HIPAA compliance.',
        'context_message': 'Healthcare organizations face unique cybersecurity challenges due to the sensitive nature of patient data and regulatory requirements.'
    },
    'financial': {
        'name': 'Financial',
        'icon': 'fa-dollar-sign',
        'class': 'text-success',
        'description': 'Comprehensive cybersecurity training for financial sector professionals, emphasizing data protection and regulatory compliance.',
        'context_message': 'Financial institutions are prime targets for cyber attacks due to the high value of financial data and transactions.'
    },
    'education': {
        'name': 'Education',
        'icon': 'fa-graduation-cap',
        'class': 'text-primary',
        'description': 'Tailored cybersecurity training for education professionals, focusing on protecting student data and academic resources.',
        'context_message': 'Educational institutions must protect sensitive student data while maintaining an open learning environment.'
    },
    'personal': {
        'name': 'Personal',
        'icon': 'fa-user',
        'class': 'text-info',
        'description': 'Essential cybersecurity training for individuals, covering personal data protection and online safety.',
        'context_message': 'Personal cybersecurity is crucial in today\'s digital world where personal data is increasingly valuable.'
    }
}

# Training modules for each sector
TRAINING_MODULES = {
    'healthcare': [
        {
            'id': 'hc_1',
            'title': 'HIPAA Compliance Basics',
            'description': 'Understanding HIPAA requirements and their impact on cybersecurity practices.',
            'content': '''
                <h4>HIPAA Security Rule Overview</h4>
                <p>The HIPAA Security Rule requires appropriate administrative, physical and technical safeguards to ensure the confidentiality, integrity, and security of electronic protected health information.</p>
                
                <h5>Key Requirements:</h5>
                <ul>
                    <li>Ensure the confidentiality, integrity, and availability of all e-PHI</li>
                    <li>Identify and protect against reasonably anticipated threats</li>
                    <li>Protect against reasonably anticipated impermissible uses or disclosures</li>
                    <li>Ensure compliance by workforce</li>
                </ul>
            ''',
            'quiz': {
                'questions': [
                    {
                        'text': 'What is the primary goal of the HIPAA Security Rule?',
                        'options': [
                            'To increase hospital revenue',
                            'To protect electronic protected health information',
                            'To regulate medical procedures',
                            'To manage hospital staff'
                        ],
                        'correct': 1,
                        'explanation': 'The HIPAA Security Rule specifically focuses on protecting electronic protected health information (e-PHI) through various safeguards.'
                    }
                ]
            }
        },
        {
            'id': 'hc_2',
            'title': 'Medical Device Security',
            'description': 'Protecting connected medical devices from cyber threats.',
            'content': '''
                <h4>Medical Device Cybersecurity</h4>
                <p>Connected medical devices present unique security challenges in healthcare environments.</p>
                
                <h5>Key Considerations:</h5>
                <ul>
                    <li>Device inventory and risk assessment</li>
                    <li>Network segmentation for medical devices</li>
                    <li>Regular security updates and patches</li>
                    <li>Incident response procedures for device-related incidents</li>
                </ul>
            ''',
            'quiz': {
                'questions': [
                    {
                        'text': 'What is a recommended security practice for medical devices?',
                        'options': [
                            'Connect all devices to the same network',
                            'Never update device software',
                            'Network segmentation',
                            'Disable all security features'
                        ],
                        'correct': 2,
                        'explanation': 'Network segmentation is crucial for medical devices to limit the potential impact of security incidents.'
                    }
                ]
            }
        }
    ],
    'financial': [
        {
            'id': 'fin_1',
            'title': 'Financial Data Protection',
            'description': 'Securing sensitive financial information and transactions.',
            'content': '''
                <h4>Financial Data Security</h4>
                <p>Financial institutions must implement robust security measures to protect sensitive financial data and transactions.</p>
                
                <h5>Key Areas:</h5>
                <ul>
                    <li>Encryption of financial data</li>
                    <li>Secure transaction processing</li>
                    <li>Multi-factor authentication</li>
                    <li>Regulatory compliance (PCI DSS, etc.)</li>
                </ul>
            ''',
            'quiz': {
                'questions': [
                    {
                        'text': 'Which of the following is a critical security measure for financial transactions?',
                        'options': [
                            'Single-factor authentication',
                            'Unencrypted data transfer',
                            'Multi-factor authentication',
                            'Public data storage'
                        ],
                        'correct': 2,
                        'explanation': 'Multi-factor authentication provides an additional layer of security for financial transactions by requiring multiple forms of verification.'
                    }
                ]
            }
        }
    ],
    'education': [
        {
            'id': 'edu_1',
            'title': 'Student Data Protection',
            'description': 'Safeguarding student information and academic records.',
            'content': '''
                <h4>Student Data Privacy</h4>
                <p>Educational institutions must protect student data while maintaining accessibility for authorized users.</p>
                
                <h5>Key Considerations:</h5>
                <ul>
                    <li>FERPA compliance</li>
                    <li>Secure student information systems</li>
                    <li>Access control and authentication</li>
                    <li>Data breach prevention and response</li>
                </ul>
            ''',
            'quiz': {
                'questions': [
                    {
                        'text': 'What federal law governs student data privacy in the US?',
                        'options': [
                            'HIPAA',
                            'FERPA',
                            'GDPR',
                            'CCPA'
                        ],
                        'correct': 1,
                        'explanation': 'The Family Educational Rights and Privacy Act (FERPA) is the federal law that protects student education records.'
                    }
                ]
            }
        }
    ],
    'personal': [
        {
            'id': 'per_1',
            'title': 'Personal Data Protection',
            'description': 'Protecting your personal information online.',
            'content': '''
                <h4>Personal Data Security</h4>
                <p>Individuals must take proactive steps to protect their personal information in the digital world.</p>
                
                <h5>Best Practices:</h5>
                <ul>
                    <li>Strong password management</li>
                    <li>Two-factor authentication</li>
                    <li>Safe browsing habits</li>
                    <li>Social media privacy</li>
                </ul>
            ''',
            'quiz': {
                'questions': [
                    {
                        'text': 'What is a recommended password practice?',
                        'options': [
                            'Use the same password everywhere',
                            'Share passwords with friends',
                            'Use short, simple passwords',
                            'Use unique, complex passwords'
                        ],
                        'correct': 3,
                        'explanation': 'Using unique, complex passwords for each account helps prevent unauthorized access if one account is compromised.'
                    }
                ]
            }
        }
    ]
}

# Sector training routes
@app.route('/sector-select')
@login_required
def sector_select():
    return render_template('sector_select.html')

@app.route('/sector/<sector>')
@login_required
def sector_training(sector):
    if sector not in SECTOR_CONFIG:
        abort(404)
        
    config = SECTOR_CONFIG[sector]
    return render_template('sector_training.html',
                         sector_name=config['name'],
                         sector_icon=config['icon'],
                         sector_class=config['class'],
                         sector_description=config['description'],
                         context_message=config['context_message'])

@app.route('/api/get-training-module')
@login_required
def get_training_modules():
    sector = request.args.get('sector', 'personal')
    if sector not in TRAINING_MODULES:
        return jsonify({'error': 'Invalid sector'}), 400
        
    return jsonify({'modules': TRAINING_MODULES[sector]})

@app.route('/api/get-training-module/<module_id>')
@login_required
def get_training_module(module_id):
    # Find the module across all sectors
    for sector_modules in TRAINING_MODULES.values():
        for module in sector_modules:
            if module['id'] == module_id:
                return jsonify(module)
                
    return jsonify({'error': 'Module not found'}), 404

@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/phishing-simulation')
@app.route('/phishing_simulation')
@login_required
def phishing_simulation():
    return render_template('phishing_simulation.html')

@app.route('/incident-response')
@login_required
def incident_response():
    return render_template('incident_response.html', user=current_user)

@app.route('/api/get-incident-scenario')
@login_required
def get_incident_scenario():
    scenarios = [
        {
            'id': 'incident_1',
            'title': 'Ransomware Attack',
            'description': 'Multiple employees report being locked out of their computers. A message demands cryptocurrency payment to restore access.',
            'severity': 'Critical',
            'indicators': [
                'Encrypted Files',
                'Ransom Message',
                'System Lockouts'
            ],
            'steps': [
                {
                    'question': 'What should be your first action?',
                    'options': [
                        'Pay the ransom immediately',
                        'Isolate affected systems from the network',
                        'Format all affected computers',
                        'Ignore the situation and wait'
                    ],
                    'correct': 1,
                    'explanation': 'Isolating affected systems prevents the ransomware from spreading to other machines while allowing for investigation and recovery.'
                },
                {
                    'question': 'What is the next step after isolation?',
                    'options': [
                        'Restore from recent backups',
                        'Try to crack the encryption',
                        'Negotiate with attackers',
                        'Reinstall all systems'
                    ],
                    'correct': 0,
                    'explanation': 'If recent backups are available, restoration is the fastest and safest way to recover without paying the ransom.'
                }
            ]
        },
        {
            'id': 'incident_2',
            'title': 'Data Breach Detection',
            'description': 'Security monitoring detects unusual data transfers from the customer database during off-hours.',
            'severity': 'High',
            'indicators': [
                'Unusual Network Traffic',
                'Off-hours Activity',
                'Large Data Transfers'
            ],
            'steps': [
                {
                    'question': 'How should you respond to this alert?',
                    'options': [
                        'Shut down the database immediately',
                        'Monitor and collect evidence',
                        'Delete the affected database',
                        'Ignore as it might be a false alarm'
                    ],
                    'correct': 1,
                    'explanation': 'Monitoring and collecting evidence helps understand the scope of the breach while maintaining service availability.'
                }
            ]
        }
    ]
    return jsonify({'scenario': random.choice(scenarios)})

@app.route('/api/check-incident-response', methods=['POST'])
@login_required
def check_incident_response():
    try:
        data = request.get_json()
        scenario_id = data.get('scenario_id')
        step_index = data.get('step_index')
        answer_index = data.get('answer_index')
        
        # Find the scenario
        scenarios = [
            {
                'id': 'incident_1',
                'title': 'Ransomware Attack',
                'steps': [
                    {
                        'correct': 1,
                        'explanation': 'Isolating affected systems prevents the ransomware from spreading to other machines while allowing for investigation and recovery.',
                        'incorrect_explanation': 'This action could worsen the situation. Isolation is needed first to prevent spread.'
                    },
                    {
                        'correct': 0,
                        'explanation': 'If recent backups are available, restoration is the fastest and safest way to recover without paying the ransom.',
                        'incorrect_explanation': 'This approach may not be the most effective. Restoring from backups is usually the best option.'
                    }
                ]
            },
            {
                'id': 'incident_2',
                'title': 'Data Breach Detection',
                'steps': [
                    {
                        'correct': 1,
                        'explanation': 'Monitoring and collecting evidence helps understand the scope of the breach while maintaining service availability.',
                        'incorrect_explanation': 'This action could destroy evidence or unnecessarily disrupt business operations. Monitoring and evidence collection should come first.'
                    }
                ]
            }
        ]
        
        # Find the matching scenario
        scenario = next((s for s in scenarios if s['id'] == scenario_id), None)
        if not scenario:
            return jsonify({'error': 'Invalid scenario ID'}), 400
            
        # Get the current step
        if step_index >= len(scenario['steps']):
            return jsonify({'error': 'Invalid step index'}), 400
            
        step = scenario['steps'][step_index]
        is_correct = answer_index == step['correct']
        
        response = {
            'is_correct': is_correct,
            'score_change': 10 if is_correct else -5,
            'explanation': step['explanation'] if is_correct else step['incorrect_explanation']
        }
        
        return jsonify(response)
        
    except Exception as e:
        print(f"Error in check_incident_response: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/get-scenario', methods=['GET'])
@login_required
def get_scenario():
    try:
        global ceas_df
        if ceas_df is None:
            ceas_df = load_ceas_dataset()
            
        if ceas_df is None or len(ceas_df) == 0:
            return jsonify({'error': 'Dataset not available'}), 500
            
        # Get a random email from the dataset
        email = ceas_df.sample(n=1).iloc[0]
        print(f"Selected email: {email.to_dict()}")
        
        # Create the scenario
        scenario = {
            'id': str(random.randint(1000, 9999)),
            'from': str(email['sender']),
            'subject': str(email['subject']),
            'content': str(email['body']),
            'is_phishing': bool(email['label'] == 1)
        }
        
        # Add analysis results
        scenario['analysis'] = {
            'sender': f"Sender domain: {scenario['from'].split('@')[-1]}",
            'sender_suspicious': scenario['is_phishing'],
            'urls': 'Suspicious links detected' if scenario['is_phishing'] else 'No suspicious links found',
            'urls_suspicious': scenario['is_phishing']
        }
        
        print(f"Generated scenario: {json.dumps(scenario, indent=2)}")
        return jsonify(scenario)
    except Exception as e:
        print(f"Error in get_scenario: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/check-answer', methods=['POST'])
@login_required
def check_answer():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        user_answer = data.get('is_phishing')
        actual_answer = data.get('actual_answer')
        
        if user_answer is None or actual_answer is None:
            return jsonify({'error': 'Missing required fields'}), 400
            
        is_correct = user_answer == actual_answer
        score_change = 10 if is_correct else -5
        
        feedback = {
            'is_correct': is_correct,
            'score': score_change,
            'message': 'Correct! Good job!' if is_correct else 'Incorrect. Keep practicing!',
            'explanation': get_explanation(actual_answer, is_correct)
        }
        
        return jsonify(feedback)
        
    except Exception as e:
        print(f"Error in check_answer: {str(e)}")
        return jsonify({'error': str(e)}), 500

def get_explanation(is_phishing, is_correct):
    if is_phishing:
        if is_correct:
            return "You successfully identified this phishing attempt! Key indicators included suspicious sender address and urgent language."
        else:
            return "This was a phishing email. Always be cautious of urgent requests and verify the sender's address carefully."
    else:
        if is_correct:
            return "You correctly identified this as a legitimate email. It follows proper communication protocols."
        else:
            return "This was actually a legitimate email. While it's good to be cautious, make sure to look for proper verification indicators."

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html',
                         user=current_user,
                         badges=current_user.badges,
                         certifications=current_user.certifications)

@app.route('/api/download-certificate/<int:cert_id>')
@login_required
def download_certificate(cert_id):
    cert = Certification.query.get_or_404(cert_id)
    if cert.user_id != current_user.id:
        abort(403)
        
    # Generate PDF certificate
    pdf_path = generate_certificate_pdf(cert)
    
    return send_file(pdf_path,
                    mimetype='application/pdf',
                    as_attachment=True,
                    download_name=f'certificate-{cert_id}.pdf')

@app.route('/api/download-all-certificates')
@login_required
def download_all_certificates():
    # Generate a ZIP file containing all certificates
    zip_path = generate_certificates_zip(current_user.certifications)
    
    return send_file(zip_path,
                    mimetype='application/zip',
                    as_attachment=True,
                    download_name='all-certificates.zip')

def generate_certificate_pdf(cert):
    # TODO: Implement certificate PDF generation
    # This will be implemented when you provide the certificate templates
    pass

def generate_certificates_zip(certifications):
    # TODO: Implement ZIP generation for all certificates
    # This will be implemented when you provide the certificate templates
    pass

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
