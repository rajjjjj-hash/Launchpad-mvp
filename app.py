import os
from datetime import datetime, timedelta
from flask import (
    Flask, render_template, redirect, url_for, flash, request, abort, send_from_directory, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user, current_user, UserMixin
)
from flask_wtf import FlaskForm
from werkzeug.utils import secure_filename
from wtforms import (
    StringField, PasswordField, SubmitField, TextAreaField, SelectField, FloatField,
    IntegerField, FileField
)
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, NumberRange, URL
from werkzeug.security import generate_password_hash, check_password_hash

# Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'pdf'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey_change_me'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'launchpad.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # max 5 MB upload

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

user_roles = ('founder', 'investor')

### Models ###

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    startups = db.relationship('Startup', backref='owner', lazy='dynamic')
    investments = db.relationship('InvestmentOffer', backref='investor', lazy='dynamic')
    scores = db.relationship('Score', backref='investor', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Startup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_name = db.Column(db.String(120), nullable=False)
    vision = db.Column(db.Text, nullable=False)
    product_description = db.Column(db.Text, nullable=False)
    market_size = db.Column(db.String(100), nullable=False)
    business_model = db.Column(db.String(100), nullable=False)
    pitch_deck_url = db.Column(db.String(200), nullable=True)
    pitch_deck_filename = db.Column(db.String(200), nullable=True)

    funding_ask_amount = db.Column(db.Float, default=0)
    funding_ask_percent = db.Column(db.Float, default=0)

    funding_rounds = db.relationship('FundingRound', backref='startup', lazy='dynamic')
    scores = db.relationship('Score', backref='startup', lazy='dynamic')

class FundingRound(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    startup_id = db.Column(db.Integer, db.ForeignKey('startup.id'), nullable=False)
    round_num = db.Column(db.Integer, nullable=False)
    amount_raised = db.Column(db.Float, default=0)
    equity_sold_percent = db.Column(db.Float, default=0)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    offers = db.relationship('InvestmentOffer', backref='funding_round', lazy='dynamic')

class InvestmentOffer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    funding_round_id = db.Column(db.Integer, db.ForeignKey('funding_round.id'), nullable=False)
    investor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount_offered = db.Column(db.Float, nullable=False)
    equity_offered_percent = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected

class PitchRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    startup_id = db.Column(db.Integer, db.ForeignKey('startup.id'), nullable=False)
    investor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    messages = db.relationship('PitchMessage', backref='pitch_room', lazy='dynamic')

class PitchMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pitch_room_id = db.Column(db.Integer, db.ForeignKey('pitch_room.id'), nullable=False)
    sender_role = db.Column(db.String(20), nullable=False)  # founder/investor
    sender_id = db.Column(db.Integer, nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    startup_id = db.Column(db.Integer, db.ForeignKey('startup.id'), nullable=False)
    investor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    team_score = db.Column(db.Integer, nullable=False)
    product_score = db.Column(db.Integer, nullable=False)
    market_score = db.Column(db.Integer, nullable=False)
    feedback = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

### Forms ###

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(3, 80)])
    role = SelectField('Role', choices=[(r,r.capitalize()) for r in user_roles], validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data.strip()).first():
            raise ValidationError('Username already exists. Please pick another.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(3, 80)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class StartupForm(FlaskForm):
    company_name = StringField('Company Name', validators=[DataRequired(), Length(max=120)])
    vision = TextAreaField('Company Vision', validators=[DataRequired(), Length(max=2000)])
    product_description = TextAreaField('Product Description', validators=[DataRequired(), Length(max=2000)])
    market_size = StringField('Market Size', validators=[DataRequired(), Length(max=100)])
    business_model = StringField('Business Model', validators=[DataRequired(), Length(max=100)])
    pitch_deck_url = StringField('Pitch Deck URL (Optional)', validators=[URL(require_tld=True), Length(max=200)], filters=[lambda x: x or None])
    pitch_deck_file = FileField('Pitch Deck PDF Upload (Optional)')
    funding_ask_amount = FloatField('Funding Ask Amount (USD)', validators=[DataRequired(), NumberRange(min=0)])
    funding_ask_percent = FloatField('Percentage Offered for Funding Ask (%)', validators=[DataRequired(), NumberRange(min=0, max=100)])
    submit = SubmitField('Create / Update Startup')

class InvestmentOfferForm(FlaskForm):
    amount_offered = FloatField('Investment Amount (USD)', validators=[DataRequired(), NumberRange(min=0)])
    equity_offered = FloatField('Equity Percentage Offered (%)', validators=[DataRequired(), NumberRange(min=0, max=100)])
    submit = SubmitField('Make Offer')

class ScoreForm(FlaskForm):
    team_score = IntegerField('Team Score (1-10)', validators=[DataRequired(), NumberRange(min=1, max=10)])
    product_score = IntegerField('Product Score (1-10)', validators=[DataRequired(), NumberRange(min=1, max=10)])
    market_score = IntegerField('Market Score (1-10)', validators=[DataRequired(), NumberRange(min=1, max=10)])
    feedback = TextAreaField('Feedback')
    submit = SubmitField('Submit Score & Feedback')

class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(3, 80)])
    submit = SubmitField('Update Profile')

    def validate_username(self, username):
        if username.data.strip() != current_user.username:
            if User.query.filter_by(username=username.data.strip()).first():
                raise ValidationError('Username already taken.')

### Login Manager ###

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


### Helper functions ###

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_pitch_deck_file(file_storage):
    if file_storage and allowed_file(file_storage.filename):
        filename = secure_filename(file_storage.filename)
        # append timestamp to filename
        filename = f"{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file_storage.save(filepath)
        return filename
    return None

def simulate_cap_table(startup):
    # Cap table summarizing all accepted offers per investor per round
    rounds = FundingRound.query.filter_by(startup_id=startup.id).order_by(FundingRound.round_num.asc()).all()
    cap_table = []
    equity_left = 100.0
    investor_share = {}
    for r in rounds:
        offers = InvestmentOffer.query.filter_by(funding_round_id=r.id, status='accepted').all()
        round_amount = 0.0
        round_equity = 0.0
        for offer in offers:
            round_amount += offer.amount_offered
            round_equity += offer.equity_offered_percent
            investor_share.setdefault(offer.investor.username, 0.0)
            investor_share[offer.investor.username] += offer.equity_offered_percent
        equity_left -= round_equity
        cap_table.append({
            'round_num': r.round_num,
            'amount_raised': round_amount,
            'equity_sold_percent': round_equity,
            'equity_left_percent': equity_left,
            'investor_share': investor_share.copy()
        })
    return cap_table

def is_owner_or_admin(startup):
    return current_user.is_authenticated and (current_user.role == 'founder' and startup.owner_id == current_user.id)

### Routes ###

@app.route('/')
def index():
    startups = Startup.query.all()
    return render_template('index.html', startups=startups, user=current_user if current_user.is_authenticated else None)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data.strip(), role=form.role.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user
    if user.role == 'founder':
        startups = user.startups.all()
        return render_template('founder_dashboard.html', startups=startups, user=user)
    else:
        startups = Startup.query.all()
        offers = InvestmentOffer.query.filter_by(investor_id=user.id, status='pending').all()
        return render_template('investor_dashboard.html', startups=startups, offers=offers, user=user)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = EditProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.username = form.username.data.strip()
        db.session.commit()
        flash('Profile updated.', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', form=form, user=current_user)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/startup/create', methods=['GET', 'POST'])
@login_required
def startup_create():
    if current_user.role != 'founder':
        abort(403)
    form = StartupForm()
    if form.validate_on_submit():
        filename = None
        if form.pitch_deck_file.data:
            file_data = form.pitch_deck_file.data
            filename = save_pitch_deck_file(file_data)
            if not filename:
                flash('Invalid file type for pitch deck. Only PDFs allowed.', 'danger')
                return render_template('startup_create.html', form=form, user=current_user)
        startup = Startup(
            owner=current_user,
            company_name=form.company_name.data.strip(),
            vision=form.vision.data.strip(),
            product_description=form.product_description.data.strip(),
            market_size=form.market_size.data.strip(),
            business_model=form.business_model.data.strip(),
            pitch_deck_url=form.pitch_deck_url.data.strip() if form.pitch_deck_url.data else None,
            pitch_deck_filename=filename,
            funding_ask_amount=form.funding_ask_amount.data,
            funding_ask_percent=form.funding_ask_percent.data
        )
        db.session.add(startup)
        db.session.commit()
        flash('Startup profile created.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('startup_create.html', form=form, user=current_user)

@app.route('/startup/<int:startup_id>')
@login_required
def startup_view(startup_id):
    startup = Startup.query.get_or_404(startup_id)
    owner = (current_user.is_authenticated and current_user.role == 'founder' and startup.owner_id == current_user.id)
    return render_template('startup_view.html', startup=startup, owner=owner, user=current_user)

@app.route('/funding/<int:startup_id>', methods=['GET', 'POST'])
@login_required
def funding_simulation(startup_id):
    startup = Startup.query.get_or_404(startup_id)
    user = current_user
    form = InvestmentOfferForm()
    # Get or create latest funding round
    current_round = FundingRound.query.filter_by(startup_id=startup.id).order_by(FundingRound.round_num.desc()).first()
    if not current_round:
        current_round = FundingRound(startup_id=startup.id, round_num=1)
        db.session.add(current_round)
        db.session.commit()

    if user.role == 'investor' and form.validate_on_submit():
        offer = InvestmentOffer(
            funding_round_id=current_round.id,
            investor_id=user.id,
            amount_offered=form.amount_offered.data,
            equity_offered_percent=form.equity_offered.data,
            status='pending'
        )
        db.session.add(offer)
        db.session.commit()
        flash('Investment offer submitted.', 'success')
        return redirect(url_for('funding_simulation', startup_id=startup.id))

    offers = InvestmentOffer.query.filter_by(funding_round_id=current_round.id).all()
    cap_table = simulate_cap_table(startup) if current_user.role == 'founder' and startup.owner_id == user.id else None
    return render_template('funding_simulation.html', startup=startup, current_round=current_round, offers=offers, user=user, form=form, cap_table=cap_table)

@app.route('/funding/offer/<int:offer_id>/<string:action>')
@login_required
def funding_offer_action(offer_id, action):
    offer = InvestmentOffer.query.get_or_404(offer_id)
    startup = offer.funding_round.startup
    if current_user.role != 'founder' or startup.owner_id != current_user.id:
        abort(403)
    if action == 'accept':
        offer.status = 'accepted'
        offer.funding_round.amount_raised += offer.amount_offered
        offer.funding_round.equity_sold_percent += offer.equity_offered_percent
        db.session.commit()
        flash('Offer accepted.', 'success')
    elif action == 'reject':
        offer.status = 'rejected'
        db.session.commit()
        flash('Offer rejected.', 'info')
    else:
        flash('Invalid action.', 'danger')
    return redirect(url_for('funding_simulation', startup_id=startup.id))

@app.route('/pitchroom/<int:startup_id>/<int:investor_id>')
@login_required
def pitch_room(startup_id, investor_id):
    startup = Startup.query.get_or_404(startup_id)
    if current_user.role == 'founder' and current_user.id != startup.owner_id:
        abort(403)
    if current_user.role == 'investor' and current_user.id != investor_id:
        abort(403)
    pitch_room = PitchRoom.query.filter_by(startup_id=startup_id, investor_id=investor_id).first()
    if not pitch_room:
        pitch_room = PitchRoom(
            startup_id=startup_id,
            investor_id=investor_id,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow() + timedelta(minutes=30)
        )
        db.session.add(pitch_room)
        db.session.commit()
    messages = PitchMessage.query.filter_by(pitch_room_id=pitch_room.id).order_by(PitchMessage.timestamp).all()
    return render_template('pitch_room.html', startup=startup, investor_id=investor_id, pitch_room=pitch_room, messages=messages, user=current_user)

@app.route('/pitchroom/<int:pitch_room_id>/send', methods=['POST'])
@login_required
def pitchroom_send_message(pitch_room_id):
    pitch_room = PitchRoom.query.get_or_404(pitch_room_id)
    # Authorize user
    if not (current_user.role == 'founder' and current_user.id == pitch_room.startup.owner_id) and not (current_user.role == 'investor' and current_user.id == pitch_room.investor_id):
        abort(403)
    content = request.form['content'].strip()
    if not content:
        flash('Message cannot be empty.', 'warning')
        return redirect(url_for('pitch_room', startup_id=pitch_room.startup_id, investor_id=pitch_room.investor_id))
    msg = PitchMessage(
        pitch_room_id=pitch_room_id,
        sender_role=current_user.role,
        sender_id=current_user.id,
        content=content
    )
    db.session.add(msg)
    db.session.commit()
    return redirect(url_for('pitch_room', startup_id=pitch_room.startup_id, investor_id=pitch_room.investor_id))

@app.route('/score/<int:startup_id>/<int:investor_id>', methods=['GET', 'POST'])
@login_required
def scoring(startup_id, investor_id):
    if current_user.role != 'investor' or current_user.id != investor_id:
        abort(403)
    startup = Startup.query.get_or_404(startup_id)
    existing_score = Score.query.filter_by(startup_id=startup_id, investor_id=investor_id).first()
    form = ScoreForm(obj=existing_score)
    if form.validate_on_submit():
        if existing_score:
            existing_score.team_score = form.team_score.data
            existing_score.product_score = form.product_score.data
            existing_score.market_score = form.market_score.data
            existing_score.feedback = form.feedback.data.strip()
            existing_score.timestamp = datetime.utcnow()
        else:
            score = Score(
                startup_id=startup_id,
                investor_id=investor_id,
                team_score=form.team_score.data,
                product_score=form.product_score.data,
                market_score=form.market_score.data,
                feedback=form.feedback.data.strip()
            )
            db.session.add(score)
        db.session.commit()
        flash('Score & feedback saved.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('scoring.html', startup=startup, investor_id=investor_id, existing_score=existing_score, form=form)

@app.route('/leaderboard')
def leaderboard():
    startups = Startup.query.all()
    leaderboard_data = []
    for s in startups:
        rounds = FundingRound.query.filter_by(startup_id=s.id).all()
        total_raised = sum(r.amount_raised for r in rounds)
        total_equity_sold = sum(r.equity_sold_percent for r in rounds)
        valuation = 0
        if total_equity_sold > 0:
            valuation = (total_raised / total_equity_sold) * 100
        investor_interest = InvestmentOffer.query.join(FundingRound).filter(
            FundingRound.startup_id==s.id,
            InvestmentOffer.status=='accepted').count()
        leaderboard_data.append({
            'startup': s,
            'valuation': valuation,
            'funding_received': total_raised,
            'investor_interest': investor_interest,
        })
    leaderboard_data.sort(key=lambda x: x['valuation'], reverse=True)
    return render_template('leaderboard.html', leaderboard=leaderboard_data, user=current_user if current_user.is_authenticated else None)

@app.route('/pitchroom/<int:pitch_room_id>/messages')
@login_required
def pitchroom_messages(pitch_room_id):
    msgs = PitchMessage.query.filter_by(pitch_room_id=pitch_room_id).order_by(PitchMessage.timestamp).all()
    messages = []
    for m in msgs:
        messages.append({
            'sender_role': m.sender_role,
            'content': m.content,
            'timestamp': m.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })
    return jsonify(messages)

# Error handlers
@app.errorhandler(413)
def request_entity_too_large(error):
    flash("File too large. Maximum size is 5MB.", "danger")
    return redirect(request.url or url_for('dashboard')), 413

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', user=current_user if current_user.is_authenticated else None), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html', user=current_user if current_user.is_authenticated else None), 403

# Add simulate_cap_table function to Jinja2 globals for template access
app.jinja_env.globals.update(simulate_cap_table=simulate_cap_table)

# Seed command for demo data
@app.cli.command('seed')
def seed_data():
    from random import randint, uniform, choice
    db.drop_all()
    db.create_all()

    print("Seeding demo users and startups...")

    founder1 = User(username='alice', role='founder')
    founder1.set_password('password')
    founder2 = User(username='bob', role='founder')
    founder2.set_password('password')
    investor1 = User(username='carol', role='investor')
    investor1.set_password('password')
    investor2 = User(username='dave', role='investor')
    investor2.set_password('password')
    db.session.add_all([founder1, founder2, investor1, investor2])
    db.session.commit()

    s1 = Startup(
        owner=founder1,
        company_name='EcoTech',
        vision='Create sustainable and affordable eco-friendly tech.',
        product_description='Smart solar panels with IoT monitoring.',
        market_size='Large',
        business_model='B2B SaaS',
        funding_ask_amount=500000,
        funding_ask_percent=15
    )
    s2 = Startup(
        owner=founder2,
        company_name='HealthPlus',
        vision='Revolutionize healthcare with AI diagnostics.',
        product_description='AI app for early disease detection.',
        market_size='Huge',
        business_model='Subscription',
        funding_ask_amount=750000,
        funding_ask_percent=10
    )
    db.session.add_all([s1, s2])
    db.session.commit()

    fr1 = FundingRound(startup_id=s1.id, round_num=1)
    fr2 = FundingRound(startup_id=s2.id, round_num=1)
    db.session.add_all([fr1, fr2])
    db.session.commit()

    offer1 = InvestmentOffer(funding_round_id=fr1.id, investor_id=investor1.id, amount_offered=250000, equity_offered_percent=7, status='accepted')
    offer2 = InvestmentOffer(funding_round_id=fr1.id, investor_id=investor2.id, amount_offered=100000, equity_offered_percent=3, status='pending')
    offer3 = InvestmentOffer(funding_round_id=fr2.id, investor_id=investor1.id, amount_offered=350000, equity_offered_percent=5, status='rejected')
    db.session.add_all([offer1, offer2, offer3])
    db.session.commit()

    print("Seed data inserted. Users: alice/bob (founders), carol/dave (investors) - all password: 'password'")

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True,port=5008)

