from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from flask_socketio import join_room, send, SocketIO
import random
from string import ascii_uppercase
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField, IntegerField, DateField, TimeField,  SelectField, RadioField
from wtforms.validators import DataRequired, NumberRange, Length, Optional, ValidationError
from flask_wtf.file import FileField, FileAllowed
from datetime import date, datetime
from PIL import Image
from werkzeug.utils import secure_filename
import pytz, io
import os, secrets
from sqlalchemy import func, or_, asc, case
import csv 
MALAYSIA_TZ = pytz.timezone("Asia/Kuala_Lumpur")
UTC = pytz.utc

# Import Flask and required extensions
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///ebfit.db"
# Secret key is used by Flask to:
# - Secure sessions
# - Protect against CSRF attacks
# - Sign cookies
# (Should be kept secret in production, usually stored in environment variables)
app.config["SECRET_KEY"] = "060226*"
db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
# Uploaded files (e.g., profile pictures, post images)
# will be stored in "static/uploads" and "static/profile_pics" folder.
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
# Restrict maximum upload file size (10 MB here).
# Helps prevent server overload due to very large uploads.
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 *1024

#--- Navbar unread notifications counter ---
@app.context_processor
def notif_count():
    if current_user.is_authenticated:
        count = Notification.query.filter_by(email=current_user.email, is_read=False).count()
        return {"unread_count": count}
    return {"unread_count": 0}


Security_Questions = [
    ("pet","What was your first pet name?"),
    ("car","What was your first car?"),
    ("hospital","What hospital name were you born in?"),
    ("city", "What city were you born in?"),
    ("girlfriend", "What was your first ex girlfriend's name?"),
    ("boyfriend", "What was your first ex boyfriend's name?"),
    ("school", "What was the name of your first school?"),
    ("book", "What was your favorite childhood book?")
]

# User database
class User(db.Model, UserMixin):
    __tablename__ = "users"
    email = db.Column(db.String(255), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    sport_level = db.Column(db.String(50), nullable=False)
    security_question = db.Column(db.String(255), nullable=False)
    security_answer = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    image_file = db.Column(db.String(255), nullable=False, default="default_image.png")
    bio = db.Column(db.Text, default="This user has not added a bio yet.", nullable=False)
    role = db.Column(db.String(20), default="user") 
    is_suspended = db.Column(db.Boolean, default=False) # True = account suspended (blocked from login)
    posts = db.relationship("Posts", back_populates="user", lazy=True, cascade="all, delete-orphan")
    # back_populates="..."= Matches relationship defined in Posts model
    # cascade="..."= If user is deleted → delete their posts as well (to avoid orphan records)

    # One-to-many: User → JoinActivities
    join_activities = db.relationship("JoinActivity", back_populates="user", lazy=True, cascade="all, delete-orphan")
    def get_id(self):
        return self.email

class Admin(db.Model):
    __tablename__ = "admins"   

    email = db.Column(db.String(255), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)


class AdminRequest(db.Model):
    __tablename__ = "admin_request"

    approval_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    join_reason = db.Column(db.Text, nullable=False)
    approval = db.Column(db.String(20), default="pending")  # pending / approved / rejected
    security_question = db.Column(db.String(255), nullable=False) 
    security_answer = db.Column(db.String(255), nullable=False)  

# POSTS DATABASE MODEL
class Posts(db.Model):
    __tablename__ = "posts" # Explicitly name the table "posts"

    post_id = db.Column(db.Integer, primary_key=True) # Unique identifier for each post
    title = db.Column(db.String(200), nullable=False) # Short title of the post/activity
    content = db.Column(db.Text, nullable=False) # Full description of the activity
    location = db.Column(db.String(100), nullable=False) # Where the activity happens
    event_date = db.Column(db.Date, nullable=False) # Activity date
    start_time = db.Column(db.Time, nullable=False) # Activity start time
    end_time = db.Column(db.Time, nullable=False) # Activity end time
    date_posted = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    post_status = db.Column(db.String(20), default="open")
    participants = db.Column(db.Integer, nullable=False) # Max or current number of participants
    image_filename = db.Column(db.String(200), nullable=True) # Optional: image uploaded for this post 
    # FK to user
    email = db.Column(db.String(255), db.ForeignKey("users.email"), nullable=False)  # Foreign key → link each post to the user who created it
    # Bidirectional relationship → allows:
    # post.user → get the owner of this post
    # user.posts → get all posts by this user
    user = db.relationship("User", back_populates="posts") 
    is_hidden = db.Column(db.Boolean, default=False) # If True → hide this post from public views 

    join_activities = db.relationship("JoinActivity", back_populates="post", lazy=True, cascade="all, delete-orphan")

    # Each report belongs to ONE post
    # Each post can have MANY reports
    # cascade="all, delete-orphan" → if a post is deleted, its reports are deleted too
    reports = db.relationship( 
        "Reports",
        backref="post",                # enables Reports.post
        lazy=True,
        cascade="all, delete-orphan"  # deleting a post deletes reports
    )

# REPORTS DATABASE MODEL
class Reports(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True) # Unique identifier for each report
    post_id = db.Column(db.Integer, db.ForeignKey("posts.post_id"), nullable=False) # The post that was reported (foreign key links to Posts table)
    reporter_email = db.Column(db.String(255), nullable=False)  # Email of the person who reported (can be user OR admin)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow) # When the report was created (auto-filled with current UTC time)


class JoinActivity(db.Model):
    __tablename__ = "join_activities"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), db.ForeignKey("users.email"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.post_id"), nullable=False)
    status = db.Column(db.String(20), default="pending")  # pending / accepted / rejected

    user = db.relationship("User", back_populates="join_activities", lazy=True)
    post = db.relationship("Posts", back_populates="join_activities", lazy=True)
#done by LeeEeWen (StudentID:243FC245ST)    
def load_locations():
    csv_path = os.path.join("instance", "locations.csv") #build path for csv file 
    choices = [] #hold formatted output

    if os.path.exists(csv_path):
        locations = [] 
        with open(csv_path, "r", encoding="utf-8") as f: 
            reader = csv.DictReader(f) #reads the CSV file into dictionary(key= name,distance)
            for row in reader:
                if row.get("name") and row.get("distance"): #ensure each row have name and distance value
                    try:
                        name = row["name"].strip() #removes extra spaces from the location name.
                        distance = float(row["distance"]) #converts the distance from string to number.
                        locations.append((name, f"{name} ({distance}km)", distance)) #append tuple into locations
                    except ValueError:
                        continue  # skip invalid distances

        # line sort by distance
        locations.sort(key=lambda x: x[2]) #third elements of tuple(distance)
        # only keep (value save in db, formatted label tht user see)
        choices = [(loc[0], loc[1]) for loc in locations]

    return choices

    
# ACTIVITY FORM (WTForms)
class ActivityForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()]) # Activity title (must not be empty)
    image = FileField("Upload Image", validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Images only!')]) # Optional image upload, but only allows specific formats
    content = TextAreaField("Content", validators=[DataRequired()]) # Detailed description of the activity (required)
    location = SelectField("Location", choices=[], validators=[DataRequired()]) # Dropdown list of locations (choices loaded dynamically later)
    event_date = DateField("Activity Date", format="%Y-%m-%d", validators=[DataRequired()]) # Date of the activity (must not be in the past → see custom validator)
    start_time = TimeField("Start Time", format="%H:%M", validators=[DataRequired()]) # Start time of the activity
    end_time = TimeField("End Time", format="%H:%M", validators=[DataRequired()]) # End time of the activity
    participants = IntegerField("Required Participants", validators=[DataRequired(), NumberRange(min=1)]) # Number of people required (must be at least 1)
    submit = SubmitField("Post") # Button to submit the form

    #Ensure the event date is not in the past.
    def validate_event_date(form, field): 
        if field.data < date.today():
            raise ValidationError("Event date must be today or in the future.")

    #Ensure the end time is after the start time.
    def validate_end_time(form, field): 
        if form.start_time.data and field.data <= form.start_time.data:
            raise ValidationError("End time must be after start time.")

# done by Hen Ee Von (StudentID: 243FC243KK)
# --- Chat message model ---
class ChatMessage(db.Model):
    __tablename__ = "chat_messages"

    id = db.Column(db.Integer, primary_key=True) #unique ID for each chat message
    post_id = db.Column(db.Integer, nullable=False, index=True) #Link the messages to a specific post
    conversation = db.Column(db.String(600), nullable=False, index=True) #Conversation key is to ensure owner and user messages stay in one thread
    sender_email = db.Column(db.String(255), nullable=False)  #Email of the sender
    sender_name = db.Column(db.String(255), nullable=False) #Name of the sender
    text = db.Column(db.Text, nullable=False) # Message content
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True) #Timestamp when the message is created

question = {
    "pet": "What was your first pet name?",
    "car": "What was your first car?",
    "hospital": "What hospital name were you born in?",
    "city": "What city were you born in?",
    "girlfriend": "What was your first ex girlfriend's name?",
    "boyfriend": "What was your first ex boyfriend's name?",
    "school": "What was the name of your first school?",
    "book": "What was your favorite childhood book?"
}

# done by Hen Ee Von (StudentID: 243FC243KK)
# --- Update Profile database ---
class UpdateProfileForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired(), Length(min=2, max=50)]) #User's full name
    gender = SelectField("Gender", choices=[("Male", "Male"), ("Female", "Female")]) #Gender options
    sport_level = SelectField("Fitness Level", choices=[("newbie","Newbie"),("intermediate","Intermediate"),("advanced","Advanced")], validators=[DataRequired()]) #Fitness level
    bio = TextAreaField("Bio", validators=[Length(max=200)]) #bio to introduce themselves
    security_question = SelectField("Security Question", choices=question, validators=[DataRequired()])
    security_answer = StringField("Security Answer", validators=[DataRequired(), Length(max=255)])
    picture = FileField("Update Profile Picture", validators=[FileAllowed(["jpg", "png"])]) #Upload new profile picture
    submit = SubmitField("Update") #Button to save profile updates

# done by Hen Ee Von (StudentID: 243FC243KK)
# --- Notifications model ---
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True) #unique ID for each notification
    email = db.Column(db.String(255), db.ForeignKey("users.email"), nullable=False) #user who will receive this notification (linked to User table)
    text = db.Column(db.String(500), nullable=False) #the content/message of the notification
    link = db.Column(db.String(500), nullable=True) #link to redirect when clicking the notifications
    is_read = db.Column(db.Boolean, default=False) #Status: False means unread, True means read
    created_at = db.Column(db.DateTime, default=datetime.utcnow) #Timestamp when the notification is created

def add_notification(email, text, link=None): #Safely add a new notification for a user
    try:
        db.session.add(Notification(email=email, text=text, link=link)) #Insert notification
        db.session.commit() #Save to database
    except Exception:
        db.session.rollback() #Rollback if error occurs

def save_profile_picture(uploaded, owner_email=None,old_filename=None): # define the folder path to store profile pics inside static/profile_pics
    folder = os.path.join(current_app.root_path, "static", "profile_pics")
    os.makedirs(folder, exist_ok=True) # Create folder if it doesn't exist

    if owner_email: # Decide the filename prefix based on who owns the picture
        prefix_src = owner_email
    elif getattr(current_user, "is_authenticated", False):
        prefix_src = current_user.email # If logged in, use current_user's email
    else:
        prefix_src = "user" # Fallback

    prefix = secure_filename(prefix_src.split("@")[0]) # Only safe characters and take before @
    filename = f"{prefix}_{secure_filename(uploaded.filename)}" # Combine prefix with original filename
    path = os.path.join(folder, filename) # Full save path

    if old_filename and old_filename != "default_image.png": # If an old picture exists(not default), try to remove it first
        old_path = os.path.join(folder, old_filename)
        if os.path.exists(old_path):
            try:
                os.remove(old_path) # Delete old file
            except PermissionError: # If file is locked, rename then delete
                tmp = old_path + ".old"
                try:
                    os.replace(old_path, tmp)
                    os.remove(tmp)
                except Exception:
                    pass # Fail silently if still not deletable
    try: # Reset file stream pointer before saving
        uploaded.stream.seek(0)
    except Exception:
        pass # Ignore if seek not supported

    uploaded.save(path) # Save the new file
    return filename # Return the new filename to store in database

# User loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(email=user_id).first()


# CUSTOM JINJA TEMPLATE FILTER
# This filter lets us format dates easily inside HTML templates.
@app.template_filter("datetimeformat")
# Convert different types of date values into a human-readable format.Default format: DD/MM/YYYY.
def datetimeformat(value, format="%d/%m/%Y"):
    """Convert YYYY-MM-DD or datetime into DD/MM/YYYY"""
    if not value:
        return "" # If no value, return empty string (avoid errors)
    try:
        # If value is a datetime
        if isinstance(value, datetime):
            return value.strftime(format)

        # If 'value' is a string like '2025-09-27'
        if isinstance(value, str):
            try: # Convert from YYYY-MM-DD → DD/MM/YYYY
                return datetime.strptime(value, "%Y-%m-%d").strftime(format)
            except ValueError:
                return value  # If string isn't a date, just return as-is
    except Exception:
        return value # Catch any unexpected errors and return original value

#done by LeeEeWen (StudentID:243FC245ST)    
# Home page
@app.route("/")
def home():
    return render_template("home.html")

#done by LeeEeWen (StudentID:243FC245ST)    
# Register page（show for and submit form)
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Get and normalize form data
        email = request.form.get("email", "").strip().lower()
        name = request.form.get("name", "").strip()
        gender = request.form.get("gender", "").strip()
        sport_level = request.form.get("sport_level", "").strip()
        security_question = request.form.get("security_question", "").strip().lower()
        security_answer = request.form.get("security_answer", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not (email and name and password): #ensure required field not empty
            flash("Please fill in all required fields.")
            return redirect(url_for("register"))

        # Hash the password
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        picture_file = "default_image.png" #default image if not file uploaded for profile picture
        if "picture" in request.files and request.files["picture"].filename:
            picture_file = save_profile_picture(request.files["picture"], email)

        # Create user
        new_user = User(
            email=email,
            name=name,
            gender=gender,
            sport_level=sport_level,
            security_question=security_question,
            security_answer=security_answer,
            password=hashed_password,
            role="user",  # default role
            image_file=picture_file,
        )

        try:
            db.session.add(new_user)#save to db
            db.session.commit()

            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))  # direct to login page

        except IntegrityError: 
            db.session.rollback()
            flash("Email already exists. Please log in.", "warning")
            return redirect(url_for("login"))

    return render_template("register.html", question=question)

#done by LeeEeWen (StudentID:243FC245ST)    
# Login page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST": #user submit form
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        user = User.query.filter_by(email=email).first() #fetch by email

        if not user:
            flash("Email not found.")
            return redirect(url_for("login"))

        if not check_password_hash(user.password, password):
            flash("Incorrect password. Please try again.")
            return redirect(url_for("login"))

        if user.is_suspended:
            flash("Your account has been suspended. Contact admin for support.", "danger")
            return redirect(url_for("login"))

        # Login successful
        login_user(user)

        if user.role == 'admin': #set session role 
            session['as_admin'] = True
        else:
            session['as_admin'] = False


        flash(f"Welcome back, {user.name}!")

        # Redirect based on role
        if user.role == "user":
            return redirect(url_for("posts"))   
        else:
            return redirect(url_for("admin_dashboard"))           

    return render_template("login.html")

#done by LeeEeWen (StudentID:243FC245ST)    
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        step = request.form.get("current") #get value from name="current" in templates

        # Step 1: Enter email(If valid, show security question.)
        if step == "email":
            email = request.form.get("email", "").strip().lower()
            user = User.query.filter_by(email=email).first() #return first matching results

            if not user:
                flash("Email not found.", "warning")
                return render_template("login.html", open_reset_modal=True, question=question)

            security_question = question.get( #look for key inside dictionary
                #retrieves the stored security question key
                user.security_question.strip().lower(),
                "Security question not found" #if sec doesnt exist
            )

            return render_template(
                "login.html",
                open_reset_modal=True,
                email=email,
                security_question=security_question,
                question=question
            )

        # Step 2: Submit answer & new password
        elif step == "reset":
            email = request.form.get("email", "").strip().lower()
            answer = request.form.get("security_answer", "").strip().lower() #get answer from user
            new_password = request.form.get("new_password", "") 

            user = User.query.filter_by(email=email).first()
            if not user:
                flash("Email not found.", "warning")
                return render_template("login.html", open_reset_modal=True, question=question)

            if user.security_answer.lower() == answer:
                user.password = generate_password_hash(new_password, method="pbkdf2:sha256") #hash new password
                db.session.commit() #update in database
                add_notification(user.email, "Your password was reset successfully.")
                flash("Password updated successfully!")
                return redirect(url_for("login"))
            else:
                flash("Security answer incorrect.", "danger")
                #render templates but keep the modal open(email stay filled in and correct security question)
                return render_template(
                    "login.html",
                    open_reset_modal=True,
                    email=email,
                    security_question=question.get(
                        user.security_question.strip().lower(),
                        "Security question not found"
                    ),
                    question=question
                )

    # Default: show reset modal
    return render_template("login.html", open_reset_modal=True, question=question)

# done by Khaw Pei Qi (StudentID: 243FC2456P)
# ROUTE: Show All Posts (/index)
@app.route("/index")
@login_required # Only logged-in users can access this page
def posts():
    #Displays the posts feed (like homepage). Shows only non-hidden posts and converts timestamps into Malaysia time.
    posts = Posts.query.filter_by(is_hidden=False).order_by(Posts.date_posted.desc()).all() # 1. Get all posts that are NOT hidden, newest first

    # 2. Convert each post's UTC timestamp → Malaysia local time
    for post in posts:
        if post.date_posted:
            # If datetime has no timezone info, assume UTC
            if post.date_posted.tzinfo is None:
                utc_time = pytz.utc.localize(post.date_posted)
            else:
                utc_time = post.date_posted
            # Convert UTC → Malaysia timezone
            post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ)
        else:
            post.local_date_posted_value = None

    # 3. Render the posts in index.html
    return render_template(
        "index.html",
        posts=posts,
        is_admin=current_user.role == "admin" if current_user.is_authenticated else False # Pass a flag to template: is the user an admin?
    )

# done by Hen Ee Von (StudentID: 243FC243KK)
# --- Search posts by keyword or event date
@app.route("/search", methods=["GET"])
def search(): 
    #Allow user to search posts by keyword (title/content/location/author name)
    #Also supports filtering posts by event date

    # Get user search input
    post_keyword = (request.args.get("post_keyword") or "").strip().lower() #keyword entered by user
    dateinpost = (request.args.get("date") or "").strip() #event date entered by user
    searched = False # flag to check if any search was done

    # Join posts with user so we can also filter by author name
    query = Posts.query.join(User).filter(Posts.is_hidden == False)

    # Filter by keyword
    if post_keyword:
        searched = True # Mark search as active
        query = query.filter(   # Look for matches in these field:
            or_(
                func.lower(Posts.title).like(f"%{post_keyword}%"), # Post title
                func.lower(Posts.content).like(f"%{post_keyword}%"), # Post content
                func.lower(Posts.location).like(f"%{post_keyword}%"), # Post location
                func.lower(User.name).like(f"%{post_keyword}%")  # Author's name(from User table)
                                                          # ✅ works because Posts has FK -> User
            )
        )

    # Filter by event date
    if dateinpost:
        searched = True
        try:
            date_obj = datetime.strptime(dateinpost, "%Y-%m-%d").date() #Convert string to date
            query = query.filter(Posts.event_date == date_obj) # Match posts on that date
        except ValueError:
            flash("Invalid date format. Please use YYYY-MM-DD.", "warning") #Show warning if wrong date format

    # run search and sort by newest posts first
    results = query.order_by(Posts.date_posted.desc()).all()

    # Convert posted date to Malaysia timezone
    for post in results: 
        if post.date_posted:
            if post.date_posted.tzinfo is None: #if no timezone info, assume UTC
                utc_time = pytz.utc.localize(post.date_posted)
            else:
                utc_time = post.date_posted
            post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ) # Convert into malaysia time
        else:
            post.local_date_posted_value = None # No date available

    # Detect if admin is logged in (for template use)
    current_admin = None
    if session.get("admin_email"): # if session has admin email
        current_admin = Admin.query.get(session.get("admin_email"))

    #render search results in index.html
    return render_template(
        "index.html",
        posts=results, # Pass the search results
        searched=searched, # Flag (True if a search wa performed)
        post_keyword=post_keyword, #Pass keyword input back to template
        date=dateinpost, #Pass date input back to template
        admin=current_admin, # Info about logged-in admin
        user=current_user if current_user.is_authenticated else None # Info about logged-in user
    )


# done by Khaw Pei Qi (StudentID: 243FC2456P)
# ERROR HANDLER: 404 Not Found
@app.errorhandler(404) # Catch all "Page Not Found" errors
def page_not_found(e): #Custom 404 error page.This runs when a user visits a non-existent URL.
    # Render the template '404.html' and return
    # an HTTP status code of 404 (Not Found)
    return render_template("404.html"), 404


# done by Khaw Pei Qi (StudentID: 243FC2456P)
# ROUTE: Create a new post
@app.route("/create", methods=["GET", "POST"])
def create():
    # Access control:
    # Only allow logged-in users OR logged-in admins (via session).
    if not current_user.is_authenticated and not session.get("admin_email"):
        flash("You need to log in first!", "danger")
        return redirect(url_for("login"))
    
    form = ActivityForm() # Load the Activity form

    # Reload location choices dynamically
    form.location.choices = load_locations()
    if not form.location.choices or form.location.choices == [("none", "--Please select a location--")]:
        form.location.choices = []  # fallback: no choices available
    
    # If form was submitted and is valid
    if form.validate_on_submit():
        image_file = form.image.data # uploaded image
        filename = None
        start_time = form.start_time.data
        end_time = form.end_time.data

        # Validation: End time must be after start time
        if start_time and end_time and end_time <= start_time:
            flash("End time must be after start time.", "danger")
            return render_template("create.html", form=form, current_date=date.today().isoformat())
        
        # Handle image upload securely
        if image_file: 
            filename = secure_filename(image_file.filename) # prevents unsafe filenames
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)

        try: # Create a new post object
            new_post = Posts(
                title=form.title.data,
                image_filename=filename,
                content=form.content.data,
                location=form.location.data,
                event_date=form.event_date.data,
                start_time=form.start_time.data,
                end_time=form.end_time.data,
                participants=form.participants.data,
                email=current_user.email if current_user.is_authenticated else session.get("admin_email"),
            )
            
            # Save post to the database
            db.session.add(new_post)
            db.session.commit()
            flash("Post created successfully!", "success")
            # Redirect back to homepage (index of posts)
            return redirect(url_for("posts"))
        except Exception as e:
            # Handle unexpected errors
            print("Error creating post:", e)
            flash(f"Error creating post: {e}", "danger")

    # If GET request or validation fails, reload form page
    return render_template("create.html", form=form, current_date=date.today().isoformat())


# done by Khaw Pei Qi (StudentID: 243FC2456P)
# ROUTE: Edit an existing post
@app.route("/edit/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    # Fetch the post or return 404 if not found
    post = Posts.query.get_or_404(post_id)

    # Permission check
    # - A logged-in user can edit their own post
    # - Admins can edit any post
    if current_user.is_authenticated:
        is_owner = (post.email == current_user.email)
    elif session.get("admin_email"):
        is_owner = True  # admins can edit any post
    else:
        is_owner = False

    if not is_owner:
        flash("You are not authorized to edit this post.", "danger")
        return redirect(url_for("posts"))

    # Pre-fill the form with post data
    form = ActivityForm(obj=post)

    # Reload location choices (fallback defaults if none are found)
    form.location.choices = load_locations()
    if not form.location.choices or form.location.choices == [("none", "--Please select a location--")]:
        form.location.choices = []

    # If form submitted and valid
    if form.validate_on_submit():
        start_time = form.start_time.data
        end_time = form.end_time.data

        # Validation: End time must be later than start time
        if start_time and end_time and end_time <= start_time:
            form.end_time.errors.append("End time must be after start time.")
            return render_template("edit_post.html", form=form, post=post, current_date=date.today().isoformat())

        # Update post fields with new form data
        post.title = form.title.data
        post.content = form.content.data
        post.location = form.location.data
        post.event_date = form.event_date.data
        post.start_time = start_time
        post.end_time = end_time
        post.participants = form.participants.data

        # Handle new image upload (replace old file if exists)
        if form.image.data:
            if post.image_filename:
                old_path = os.path.join(current_app.root_path, "static/uploads", post.image_filename)
                if os.path.exists(old_path):
                    os.remove(old_path) # delete old image
            file = form.image.data
            filename = secure_filename(file.filename)
            file.save(os.path.join(current_app.root_path, "static/uploads", filename))
            post.image_filename = filename
        # Commit changes to the database
        db.session.commit()
        flash("Post updated successfully!", "success")
        return redirect(url_for("post_detail", post_id=post.post_id))

    # On GET request, pre-fill the form manually (safety net)
    if request.method == "GET":
        form.title.data = post.title
        form.content.data = post.content
        form.location.data = post.location
        form.event_date.data = post.event_date
        form.start_time.data = post.start_time
        form.end_time.data = post.end_time
        form.participants.data = post.participants

    # Render the edit post page
    return render_template("edit_post.html", form=form, post=post, current_date=date.today().isoformat())


# done by Khaw Pei Qi (StudentID: 243FC2456P)
# ROUTE: Delete a post (User/Admin)
@app.route("/delete/<int:post_id>", methods=["POST"])
def delete(post_id): # Must be logged in (user or admin)
    if not current_user.is_authenticated and not session.get("as_admin"):
        flash("You must log in first.")
        return redirect(url_for("login"))

    post = Posts.query.get_or_404(post_id) # Fetch post or return 404 if not found

    #  Permission check
    # - Admin can delete any post
    # - Normal users can delete only their own post
    if session.get("as_admin"):
        can_delete = True
    else:
        can_delete = (post.email == current_user.email)

    if not can_delete:
        flash("You don't have permission to delete this post.", "danger")
        return redirect(url_for("posts"))

    # If post has an image → delete from filesystem too
    if post.image_filename:
        img_path = os.path.join(current_app.root_path, "static/uploads", post.image_filename)
        if os.path.exists(img_path):
            os.remove(img_path)

    # Delete post from database
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully!", "success")

    # Redirect admin to the correct page depending on context
    if session.get("as_admin"):
        if request.args.get("next"): # e.g. if coming from a modal
            return redirect(request.args.get("next"))
        elif request.referrer and "admin/reports" in request.referrer:
            return redirect(url_for("admin_reports"))
        elif request.referrer and "admin/dashboard" in request.referrer:
            return redirect(url_for("admin_dashboard"))
        else:
            return redirect(url_for("admin_dashboard"))

    # Normal user → go back to posts page
    return redirect(url_for("posts"))


# done by Khaw Pei Qi (StudentID: 243FC2456P)
# ROUTE: Report a post (User/Admin)
@app.route("/report/<int:post_id>", methods=["POST"])
def report_post(post_id):
    # Must be logged in (either normal user or admin)
    if not current_user.is_authenticated and not session.get("admin_email"):
        flash("You must be logged in to report posts.", "danger")
        return redirect(url_for("login"))

    # Fetch the target post
    post = Posts.query.get_or_404(post_id)

    # Reporter identity:
    # - Normal user → use current_user.email
    # - Admin → use session['admin_email']
    reporter_email = current_user.email if current_user.is_authenticated else session.get("admin_email")

    # Prevent duplicate reports by the same user/admin
    existing_report = Reports.query.filter_by(post_id=post_id, reporter_email=reporter_email).first()
    if existing_report:
        flash("You already reported this post.", "warning")
        return redirect(url_for("post_detail", post_id=post_id))

    # Create and save new report entry
    new_report = Reports(post_id=post_id, reporter_email=reporter_email)
    db.session.add(new_report)
    db.session.commit()

    # Auto-hide post if it reaches threshold (e.g. 3 reports)
    report_count = Reports.query.filter_by(post_id=post_id).count()
    if report_count >= 3:
        post.is_hidden = True
        db.session.commit()

    # Notify user of successful report
    flash("Post reported successfully.", "success")
    return redirect(url_for("posts"))


# done by Khaw Pei Qi (StudentID: 243FC2456P)
# Route to show the detail of a single post
@app.route("/post/<int:post_id>")
def post_detail(post_id):
    # Get the post from database, show 404 if not found
    post = Posts.query.get_or_404(post_id)

    # Get query parameters from the URL (optional settings)
    readonly = request.args.get("readonly", type=int) # Show as read-only 
    from_reports = request.args.get("from_reports", default=0, type=int) # Came from reports page
    from_dashboard = request.args.get("from_dashboard", default=0, type=int) # Came from dashboard
    next_url = request.args.get("next", url_for("posts")) # Where to go next after this page

    # If user is admin and readonly is not set, force readonly mode
    if session.get("admin_email") and readonly is None:
        args = request.args.to_dict(flat=True)  # Copy all current URL parameters
        args["readonly"] = 1                   # Force readonly
        args.setdefault("from_reports", from_reports)
        args.setdefault("from_dashboard", from_dashboard)
        # Redirect back to this page with readonly mode on
        return redirect(url_for("post_detail", post_id=post_id, **args))

    # Convert post date from UTC to Malaysia timezone for display
    if post.date_posted:
        utc_time = pytz.utc.localize(post.date_posted) # Make sure time is UTC
        post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ)
    else:
        post.local_date_posted_value = None # No date available

    # Get all activities related to this post
    join_activities = JoinActivity.query.filter_by(post_id=post.post_id).all()
    # Prepare list to store conversations for post owner
    owner_conversations = []

    owner_email = post.email  # Who owns this post

    # If the logged-in user is the owner, show chat partners
    if current_user.is_authenticated and current_user.email.lower() == owner_email.lower():
        # Find all distinct users who sent messages for this post
        partners = (
            db.session.query(ChatMessage.sender_email)
            .filter_by(post_id=post.post_id)
            .distinct()
        )
        # Add each partner to the list (skip owner's own email)
        for (email,) in partners:
            if email.lower() != owner_email.lower():
                user = User.query.get(email) # Get user info
                owner_conversations.append(
                    {"email": email, "name": user.name if user else email} # Use email if name not found
                )

    # Show the post detail page with all info
    return render_template(
        "post_detail.html",
        post=post,
        join_activities=join_activities,
        owner_conversations=owner_conversations,
        readonly=readonly,
        from_reports=from_reports,
        from_dashboard=from_dashboard,
        next_url=next_url, 
    )

# --- Helper for stable conversation key between two emails
def conversation_key(a_email: str, b_email: str) -> str:
    return "|".join(sorted([a_email.lower(), b_email.lower()]))

# done by Hen Ee Von (StudentID: 243FC243KK)
# --- Chat between post owner and a partner ---
@app.route("/chat/<int:post_id>/<partner_email>")
@login_required
def chat_with_user(post_id, partner_email): #Load all chat messages between current user and partner for a specific posts
    post = Posts.query.get_or_404(post_id) # Chat is tied to a post
    owner_email = post.email.lower() # Post owner
    current_email = current_user.email.lower() # User that is viewing nnow
    partner_email = partner_email.lower() # partner

    # Prevent outsiders from chatting → only owner or partner can view this chat
    if current_email != owner_email and partner_email != owner_email:
        return redirect(url_for("chat_with_user", post_id=post_id, partner_email=owner_email))

    #room ID is based on post and emails
    conv = conversation_key(current_email, partner_email) # Room key
    room = f"post-{post_id}-{conv}" # Socket.IO room name

    #load chat messages from oldest to latest messages
    messages = (
        ChatMessage.query.filter_by(post_id=post_id, conversation=conv)
        .order_by(asc(ChatMessage.created_at))
        .all()
    )

    for msg in messages: # Prepare local time label for display below each message
        if msg.created_at:
            msg.local_time = pytz.utc.localize(msg.created_at).astimezone(MALAYSIA_TZ).strftime("%H:%M")
        else:
            msg.local_time = ""

    #Partner display info (name and profile pic)
    partner_user = User.query.get(partner_email)
    partner_name = partner_user.name if partner_user else partner_email
    partner_img = url_for("static", filename=f"profile_pics/{partner_user.image_file or 'default_image.png'}") if partner_user else url_for("static", filename="profile_pics/default.png")

    #Owner sees partner name, partner sees post owner's name
    if current_email == owner_email:
        header_name = partner_name
    else:
        header_name = post.user.name  # ✅ uses Posts.user relationship

    return render_template("chat.html",post=post, room=room, username=current_user.name,header_name=header_name, 
                           messages=messages, post_id=post_id, partner_email=partner_email,partner_img=partner_img) # Render room, messages, name, profile picture

# done by Hen Ee Von (StudentID: 243FC243KK)
# --- Socket.IO(user joins a chat room)
@socketio.on("join")
def on_join(data):
    room = data.get("room") # Which room to join

    # Identify the joining user (supports user or admin session)
    if current_user.is_authenticated:
        name = current_user.name
        email = current_user.email
    elif session.get("admin_email"):
        email = session.get("admin_email")
        admin_obj = Admin.query.get(email)
        name = admin_obj.admin_name if admin_obj else "Admin"
    else:
        return  # No one logged in, ignore

    if room:
        print("JOIN ->", email, "to", room)
        join_room(room) # Join Socket.IO room
        send(f"{name} joined the chat.", to=room) #Broadcast system message

# done by Hen Ee Von (StudentID: 243FC243KK)
# --- Socket.IO to handle sending a new message
@socketio.on("send_message")
def on_send_message(data):
    room = (data or {}).get("room") # Room name
    text = ((data or {}).get("message") or "").strip() # Message
    post_id = (data or {}).get("post_id") # Tied post
    partner = ((data or {}).get("partner_email") or "").lower().strip() # Receiver

    if not (room and text and post_id and partner):
        return

    # Support both users and admins as senders
    if current_user.is_authenticated:
        current_email = current_user.email.lower()
        sender_email = current_user.email
        sender_name = current_user.name
    elif session.get("admin_email"):
        sender_email = session.get("admin_email").lower()
        current_email = sender_email
        admin_obj = Admin.query.get(sender_email)
        sender_name = admin_obj.admin_name if admin_obj else "Admin"
    else:
        return  # nobody logged in, ignore

    conv = conversation_key(current_email, partner) # Conversation key

    msg = ChatMessage(
        post_id=int(post_id),
        conversation=conv,
        sender_email=sender_email,
        sender_name=sender_name,
        text=text,
    ) # Save message in database

    db.session.add(msg)
    db.session.commit()

    if msg.created_at: # local time label 
        utc_time = pytz.utc.localize(msg.created_at)
        local_time = utc_time.astimezone(MALAYSIA_TZ)
    else:
        local_time = None

    ts = local_time.strftime("%H:%M") if local_time else ""

    try: # ✅ Notify partner if it’s not the same as sender
        if partner != current_email:
            chat_url = url_for("chat_with_user", post_id=post_id, partner_email=sender_email)
            add_notification(partner, f"{sender_name} sent you a message", link=chat_url)
    except Exception:
        db.session.rollback()

    send({"user": msg.sender_name,"email": msg.sender_email ,"text": msg.text, "time": ts}, to=room) # Emit the message to everyone in the room

# done by Hen Ee Von (StudentID: 243FC243KK)
# --- Show all notifications for the logged-in user ---
@app.route("/notifications")
@login_required
def notifications():
    rows = (
        Notification.query.filter_by(email=current_user.email) # Only this user's notifications
        .order_by(Notification.created_at.desc()) # Newest notification first
        .all()
    )

    # Prepare Malaysia time display for each notifications
    for notif in rows:
        if notif.created_at:
            if notif.created_at.tzinfo is None:
                notif.local_time = pytz.utc.localize(notif.created_at).astimezone(MALAYSIA_TZ) # assume UTC to Malaysia time
            else:
                notif.local_time = notif.created_at.astimezone(MALAYSIA_TZ) # convert existing timezone into malaysia time
        else:
            notif.local_time = None

    return render_template("notifications.html", rows=rows) # Render list page

# done by Hen Ee Von (StudentID: 243FC243KK)
# --- Mark all notifications as read(one-click)---
@app.route("/notifications/read_all", methods=["POST"])
@login_required
def notifications_read_all():
    Notification.query.filter_by(email=current_user.email, is_read=False).update({"is_read": True}) # Target only this user's unread items
    db.session.commit() #Save changes
    return redirect(url_for("notifications")) #Back to list

# done by Hen Ee Von (StudentID: 243FC243KK)
# --- Open a single notification and redirect to its link ---
@app.route("/notif/<int:notif_id>")
@login_required
def open_notif(notif_id):
    notif = Notification.query.get_or_404(notif_id) # Load notif or 404

    if notif.email.lower() == current_user.email.lower(): #Security(must belong to current user)
        notif.is_read = True # Mark as read
        db.session.commit()

    return redirect(notif.link or url_for("notifications")) # Go to target link, fallback to list

# done by Hen Ee Von (StudentID: 243FC243KK)
#Delete single notification
@app.route("/notifications/delete/<int:notif_id>", methods=["POST"])
@login_required
def notifications_delete(notif_id):
    notif = Notification.query.get_or_404(notif_id) # Load notif or 404
    if notif.email == current_user.email: #Only owner can delete
        db.session.delete(notif)
        db.session.commit()
    return redirect(url_for("notifications")) #Back to list

# done by Hen Ee Von (StudentID: 243FC243KK)
#Delete all notifications
@app.route("/notifications/clear", methods=["POST"])
@login_required
def notifications_clear():
    Notification.query.filter_by(email=current_user.email).delete() # Delete all notifications for this user
    db.session.commit()
    return redirect(url_for("notifications")) # Back to list

# done by Hen Ee Von (StudentID: 243FC243KK)
# ---My profile ---
@app.route("/profile") # Redirecr to own profile by email
@login_required
def profile():
    return redirect(url_for("profile_page", email=current_user.email)) # Convinience redirect

# done by Hen Ee Von (StudentID: 243FC243KK)
# --- View a user's profile page ---
@app.route("/profile/<string:email>")
@login_required
def profile_page(email): #Show a user's account information and their recent posts
    user = User.query.filter_by(email=email).first_or_404() # Target profile user

    # load all posts by this user
    recent_posts = (
        Posts.query.filter_by(email=user.email)
        .order_by(Posts.date_posted.desc()) # latest posts first
        .all()
    )

    # Convert posted date to Malaysia timezone
    for post in recent_posts:
        if post.date_posted:
            if post.date_posted.tzinfo is None:
                utc_time = pytz.utc.localize(post.date_posted)
                post.local_date_posted_value = utc_time.astimezone(MALAYSIA_TZ)
            else:
                post.local_date_posted_value = post.date_posted.astimezone(MALAYSIA_TZ)
        else:
            post.local_date_posted_value = None

    # correct profile picture path (use their image, not always current_user)
    image_url = url_for(
        "static",
        filename=f"profile_pics/{user.image_file or 'default_image.png'}"
    )

    return render_template(
        "profile.html",
        user=user,
        image_url=image_url,
        recent_posts=recent_posts
    ) # Render profile template


# done by Hen Ee Von (StudentID: 243FC243KK)
# --- Edit Profile(update name/gender/lvl/security Q&A/bio/profile pic) - Done by Hen Ee Von ---
@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def profile_edit():
    form = UpdateProfileForm() #WTForms form

    form.security_question.choices = list(question.items()) # Dropdown

    if form.validate_on_submit(): 
        # Update basic field
        current_user.name = form.name.data
        current_user.gender = form.gender.data
        current_user.sport_level = form.sport_level.data
        current_user.bio = form.bio.data or None
        current_user.security_question = form.security_question.data
        current_user.security_answer = (form.security_answer.data or "").strip().lower()

        # Optional for profile pic upload
        uploaded = request.files.get("picture")
        if uploaded and uploaded.filename:
            current_user.image_file = save_profile_picture(uploaded, current_user.email, current_user.image_file) # Save new file and cleanup old profile picture

        db.session.commit()
        flash("Profile updated.")
        return redirect(url_for("profile")) # Back to my Profile page
    
    if request.method == "GET": # Prefill existing values on GET
        form.name.data = current_user.name
        form.gender.data = current_user.gender
        form.bio.data = current_user.bio
        form.security_question.data = current_user.security_question
        form.security_answer.data = current_user.security_answer

    image_url = url_for("static", filename=f"profile_pics/{current_user.image_file or 'default_image.png'}")

    return render_template("edit_profile.html", form=form, image_url=image_url, question=question)

# Join Activity
@app.route("/activityrequest/<int:post_id>", methods=["POST"])
@login_required
def activityrequest(post_id):
    post = Posts.query.get_or_404(post_id) #fetch post or return 404

    if post.post_status == "closed":
        flash("This activity is already closed.")
        return redirect(url_for("post_detail", post_id=post.post_id))

    # Prevent duplicate request
    existing = JoinActivity.query.filter_by(email=current_user.email, post_id=post.post_id).first() #database query on the JoinActivity table and look for current user email and request related for specific post
    if existing:
        flash("You already requested this activity.")
    else:
        join_act = JoinActivity(email=current_user.email, post_id=post.post_id) #create a new JoinActivity record
        db.session.add(join_act) #add in db
        db.session.commit()
        flash("Your request has been sent to the post owner.")

        add_notification(
            post.email,
            f"{current_user.name} requested to join '{post.title}'",
            link=url_for("post_detail", post_id=post.post_id)
        )

    return redirect(url_for("post_detail", post_id=post.post_id))

#done by LeeEeWen (StudentID:243FC245ST)    
# Handle Join Activity requests by authors post
@app.route("/handleactivity/<int:request_id>/<string:decision>", methods=["POST"]) 
@login_required
def handle_request(request_id, decision):
    join_activity = JoinActivity.query.get_or_404(request_id) #Finds the JoinActivity record by request_id.
    post = join_activity.post

    # Only the post owner can handle requests
    if post.email != current_user.email:
        flash("You are not authorized to manage this request.")
        return redirect(url_for("post_detail", post_id=post.post_id))

    if post.post_status == "closed": #if status is closed,don’t allow further actions.
        flash("This activity is already closed.")
        return redirect(url_for("post_detail", post_id=post.post_id))

    if decision == "accept":
        accepted_count = JoinActivity.query.filter_by(post_id=post.post_id, status="accepted").count() #Count how many users have already been accepted for this activity.

        if accepted_count < post.participants:
            join_activity.status = "accepted"
            flash(f"{join_activity.user.name if join_activity.user else join_activity.email} has been accepted!") 

            add_notification(
                join_activity.email,
                f"Your request for '{post.title}' was accepted",
                link=url_for("post_detail", post_id=post.post_id)
            )

            accepted_count += 1
            if accepted_count >= post.participants:
                post.post_status = "closed"
                flash("The activity is now full and closed.")
        else:
            flash("This activity already has enough participants.")

    elif decision == "reject":
        join_activity.status = "rejected"
        flash(f"{join_activity.user.name if join_activity.user else join_activity.email} has been rejected.")

        add_notification(join_activity.email, f"Your request for '{post.title}' was rejected",link=url_for("post_detail", post_id=post.post_id))

    db.session.commit()
    return redirect(url_for("post_detail", post_id=post.post_id))


#done by LeeEeWen (StudentID:243FC245ST)    
#admin interface
# Create default first admin
def create_first_admin():
    existing_admin = User.query.filter(User.role.in_(["admin"])).first() #look in user db and look for if role is "admin".
    
    if not existing_admin: 
        admin_user = User(
            email="eewen@gmail.com",
            name="Lee Ee Wen",
            password=generate_password_hash("aaaa", method="pbkdf2:sha256"),
            gender="Female",
            sport_level="Advanced",
            security_question="book",  #  key from the question dict
            security_answer="Cinderella",
            role="admin"
        )
        db.session.add(admin_user) #if not add, default admin to database
        db.session.commit()


#done by LeeEeWen (StudentID:243FC245ST)    
# REQUEST ADMIN ACCESS
@app.route("/request_admin", methods=["GET", "POST"])
def request_admin():
    # if request is post, take the email from request.form. if request is get, get the eamil from url
    email = request.form.get("email", "").strip().lower() if request.method == "POST" else request.args.get("email", "").strip().lower()

    # Prevent existing admins from submitting requests
    existing_user = User.query.filter_by(email=email).first()
    if existing_user and existing_user.role in ["admin"]:
        flash("You are already an admin. Please log in.")
        return redirect(url_for("login"))

    # Determine step: default to "email" step1
    step = request.form.get("step", "email")

    # Step 1: show email / pre-filled form
    if step == "email" and request.method == "POST" or request.method == "GET":
        return render_template(
            "request_admin.html", #show form of the templates
            email=email,
            existing_user=existing_user, #if user is existing user, the form will auto fill email and full name
            question=question #pass security question to templates
        )

    # Step 2: submit admin full request 
    elif step == "submit" and request.method == "POST":
        join_reason = request.form.get("join_reason", "").strip() #user had filled in the form and form grab the join_reason

        # Check if a request already exists
        existing_request = AdminRequest.query.filter_by(email=email).first()
        if existing_request:
            flash("One submission per email. You have already submitted a request.")
            return redirect(url_for("request_admin"))

        if existing_user:
            # Existing user: take info from User table
            password_hash = existing_user.password
            name = existing_user.name
            sec_question = existing_user.security_question  # already stored
            sec_answer = existing_user.security_answer      # already stored
        else:
            # New user must provide all info
            name = request.form.get("name", "").strip()
            password = request.form.get("password", "").strip()
            sec_question = request.form.get("security_question", "").strip()
            sec_answer = request.form.get("security_answer", "").strip()

            if not all([name, password, sec_question, sec_answer]):
                flash("All fields are required for new users.")
                return redirect(url_for("request_admin"))

            password_hash = generate_password_hash(password, method="pbkdf2:sha256")

        # Create new admin request in database
        new_request = AdminRequest(
            email=email,
            name=name,
            password=password_hash,
            join_reason=join_reason,
            approval="pending",
            security_question=sec_question,
            security_answer=sec_answer
        )

        db.session.add(new_request)
        db.session.commit()
        flash("Your admin request has been submitted.")
        return redirect(url_for("request_admin"))

    # Default render
    return render_template("request_admin.html", question=question, email=email, existing_user=existing_user)

#done by LeeEeWen (StudentID:243FC245ST)       
# HANDLE REQUEST (any logged-in admin can approve/reject)
@app.route("/handle-request/<int:approval_id>", methods=["GET", "POST"])
@login_required
def handle_request_admin(approval_id):
    if current_user.role not in ["admin"]:
        flash("You do not have permission to perform this action.")
        return redirect(url_for("home"))
    #Fetches an AdminRequest from the database with that approval_id
    join_request = AdminRequest.query.get_or_404(approval_id)

    if request.method == "POST":
        decision = request.form.get("decision")

        if decision == "accept":
            # Look up the user email in the User table 
            user = User.query.filter_by(email=join_request.email).first()

            if user:
                # Existing user: only upgrade them to admin role
                if user.role == "user":
                    user.role = "admin"

                # Ensure security question and answer exist(if missing, get value from AdminRequest. ) 
                if not user.security_question or not user.security_answer:
                    user.security_question = join_request.security_question 
                    user.security_answer = join_request.security_answer

            else:
                # New user: take all info from the request
                new_user = User(
                    email=join_request.email,
                    name=join_request.name,
                    password=join_request.password,  
                    role="admin",
                    gender="Other",
                    sport_level="None",
                    security_question=join_request.security_question,
                    security_answer=join_request.security_answer
                )
                db.session.add(new_user)

            join_request.approval = "approved"
            db.session.commit() #add new admin into db if accepted by existing admin
            flash(f"{join_request.name} has been approved as admin.")

        elif decision == "reject":
            join_request.approval = "rejected"
            db.session.commit()
            flash(f"Request from {join_request.name} has been rejected.")

        return redirect(url_for("admin_approval"))


#done by LeeEeWen (StudentID:243FC245ST)    
# show ADMIN APPROVAL PAGE for admin know who request to join admin
@app.route("/admin_approval")
@login_required
def admin_approval():
    # check role
    if current_user.role not in ["admin"]: # If the logged-in user’s role is not "admin" , then block them.
        flash("You do not have permission to access this page.")
        return redirect(url_for("home"))

    # Fetch all and pull admin requests from the db table
    pending_requests = AdminRequest.query.filter_by(approval="pending").all()
    approved_requests = AdminRequest.query.filter_by(approval="approved").all()
    rejected_requests = AdminRequest.query.filter_by(approval="rejected").all()

    return render_template(
        "admin_approval.html",
        pending_requests=pending_requests,
        approved_requests=approved_requests,
        rejected_requests=rejected_requests
    )

#done by LeeEeWen (StudentID:243FC245ST)    
@app.route("/check_approval", methods=["GET", "POST"])
def check_approval():
    email = request.form.get("email", "").strip().lower() #Pulls email from the submitted form
    open_approval_modal = True
    approval_status = None #placeholder storing approval_status or none for not found

    if request.method == "POST" and email: #run only when user submit email
        # Looks in the AdminRequest table for a record with this email.
        req = AdminRequest.query.filter_by(email=email).first() #access approval column
        if req:
            approval_status = req.approval.lower()
        else:
            # if not found, Check if user exists and has admin role
            user = User.query.filter_by(email=email).first()
            if user and user.role in ["admin"]:
                approval_status = "approved"
            else:
                approval_status = "not_found"

        return render_template( # submit email to check validity
            "request_admin.html",
            open_approval_modal=open_approval_modal,
            approval_status=approval_status,
            submitted_email=email
        )

    return render_template( #check approval status
        "request_admin.html",
        open_approval_modal=open_approval_modal,
        approval_status=approval_status
    )

# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for("home"))


# done by Khaw Pei Qi (StudentID: 243FC2456P)
# Admin dashboard page
@app.route("/admin/dashboard")
@login_required # Make sure user is logged in
def admin_dashboard():
    # Only allow access if the user is an admin
    if current_user.role != "admin":
        abort(403)  # Stop and show "Forbidden" if not admin

    # Get all users and posts from the database
    users = User.query.all()
    posts = Posts.query.all()

    # Get all users and posts from the database
    return render_template(
        "admin_dashboard.html",
        admin=current_user, # Info about the logged-in admin
        users=users,  # List of all users
        posts=posts,  # List of all posts
        is_admin=True  # Flag to indicate admin view in the template
    )


# done by Khaw Pei Qi (StudentID: 243FC2456P)
# Admin reports page
@app.route("/admin/reports")
@login_required # Make sure the user is logged in
def admin_reports():
    # Only allow access if the user is an admin
    if current_user.role != "admin":
        abort(403)  # Stop and show "Forbidden" if not admin

    # Get posts that have been reported 3 or more times
    flagged_posts = (
        db.session.query(Posts, db.func.count(Reports.id).label("report_count"))
        .join(Reports, Reports.post_id == Posts.post_id) # Join posts with reports
        .group_by(Posts.post_id) # Group by post
        .having(db.func.count(Reports.id) >= 3)   # Only posts with 3+ reports
        .all()
    )

    # Get all users who are currently suspended
    suspended_users = User.query.filter_by(is_suspended=True).all()

    # Render the admin reports page with flagged posts and suspended users
    return render_template(
        "admin_reports.html",
        flagged_posts=flagged_posts, # List of posts with too many reports
        suspended_users=suspended_users # List of suspended users
    )

# done by Khaw Pei Qi (StudentID: 243FC2456P)
# Route to suspend a user
@app.route("/suspend/<string:email>", methods=["POST"])
@login_required # Make sure user is logged in
def suspend_user(email):
    # Only allow admins to suspend users
    if current_user.role != "admin":
        abort(403)  # Stop and show "Forbidden" if not admin

    # Find the user by email (case-insensitive), 404 if not found
    user = User.query.filter_by(email=email.lower()).first_or_404()
    # Mark the user as suspended
    user.is_suspended = True
    db.session.commit() # Save the change in the database

    flash(f"User {user.email} has been suspended.", "warning") # Show a message to confirm the suspension
    return redirect(url_for("admin_reports")) # Redirect back to the admin reports page
  

# done by Khaw Pei Qi (StudentID: 243FC2456P)
# Route to unsuspend a user
@app.route("/unsuspend/<string:email>", methods=["POST"])
@login_required # Make sure the user is logged in
def unsuspend_user(email):
    # Only allow admins to unsuspend users
    if current_user.role != "admin":
        abort(403) # Stop and show "Forbidden" if not admin

    # Find the user by email (case-insensitive), 404 if not found
    user = User.query.filter_by(email=email.lower()).first_or_404()
    # Mark the user as active (not suspended)
    user.is_suspended = False
    db.session.commit() # Save the change in the database

    flash(f"User {user.email} has been unsuspended.", "success") # Show a message to confirm the user has been unsuspended
    return redirect(url_for("admin_reports")) # Redirect back to the admin reports page



# done by Khaw Pei Qi (StudentID: 243FC2456P)
# Route to reactivate a hidden post
@app.route("/reactivate/<int:post_id>", methods=["POST"])
@login_required # Make sure the user is logged in
def reactivate_post(post_id):
    # Only allow admins to reactivate posts
    if current_user.role != "admin":
        abort(403) # Stop and show "Forbidden" if not admin

    # Find the post by ID, 404 if not found
    post = Posts.query.get_or_404(post_id)
    # Make the post visible again
    post.is_hidden = False

    # Remove all reports related to this post
    Reports.query.filter_by(post_id=post_id).delete()

    db.session.commit() # Save changes in the database
    flash("Post has been reactivated and is now visible.", "success") # Show a confirmation message
    return redirect(url_for("admin_reports")) # Redirect back to the admin reports page



@app.context_processor
def inject_admin():
    email = session.get("admin_email")
    if email:
        current_admin = Admin.query.get(email)
        return dict(admin=current_admin)
    return dict(admin=None)


# Upload location list
#done by LeeEeWen (StudentID:243FC245ST)    
@app.route("/admin/updatelocation", methods=["GET", "POST"])
@login_required
def upload_location_csv():
    if current_user.role not in ["admin"]:
        flash("Request Denied. You are not admin.")
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file") #holds all uploaded files from a form and name:file from templates input must match here
        if not file or file.filename == "":
            flash("Please select a CSV file.")
            return redirect(url_for("upload_location_csv"))

        try:
            csv_path = os.path.join("instance", "locations.csv") #file is always stored in instance/locations.csv.

            # Load existing locations
            locations = {} 
            if os.path.exists(csv_path): #Checks if the file (locations.csv) already exists in the instance/ folder.
                with open(csv_path, "r", encoding="utf-8") as f:
                    for row in csv.DictReader(f): #Reads the CSV file using csv.DictReader. each line of csv file become key, value
                        try: #gets the "name" value, and converts distance string into a float
                            locations[row["name"].strip()] = float(row["distance"]) 
                        except:
                            continue #if the row missing, it will skip reading

            #read csv files ,parses the CSV into dictionaries and ensures the file stream is read as text (UTF-8).
            reader = csv.DictReader(io.TextIOWrapper(file.stream, encoding="utf-8")) 
            if not {"name", "distance"}.issubset(reader.fieldnames):#check required column
                flash("CSV must have 'name' and 'distance' columns.") 
                return redirect(url_for("upload_location_csv"))

            new_or_updated = 0 #initialize counter
            for row in reader:
                try:
                    name, dist = row["name"].strip(), float(row["distance"]) #get name and distance of location convert to float
                    if name not in locations or locations[name] != dist: #new location or name exist but distance change
                        locations[name] = dist
                        new_or_updated += 1
                except:
                    continue

            if not new_or_updated:
                flash("No new or updated locations found.")
                return redirect(url_for("upload_location_csv"))

            # Save sorted
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["name", "distance"]) #Writes the first row (name,distance)
                writer.writeheader()
                #locations.items() give key-value pairs from the dictionary, take each pair (name, distance)and compare with the secondelement (x[1] → distance) and sort by that value.
                for n, d in sorted(locations.items(), key=lambda x: x[1]): 
                    # write name and distance with formats the distance as a number with 2 decimal places.
                    writer.writerow({"name": n, "distance": f"{d:.2f}"})

            flash(f"Upload successful! {new_or_updated} location(s) added/updated.")
        except Exception as e:
            flash(f"Error uploading CSV: {e}")

        return redirect(url_for("upload_location_csv"))

    return render_template("uploadlocation.html")

@app.route("/user/<string:email>")
@login_required
def view_user_profile(email):
    user = User.query.get_or_404(email)
    return render_template("profile.html", user=user)

# done by Khaw Pei Qi (StudentID: 243FC2456P)
# Route to switch user to admin view
@app.route("/switch_to_admin")
def switch_to_admin():
    # Only allow if user is logged in and is an admin
    if not current_user.is_authenticated or current_user.role != 'admin':
        flash("You cannot switch to admin view.", "danger") # Show error
        return redirect(url_for('posts')) # Redirect to posts page

    # Mark the session as admin view
    session['as_admin'] = True
    flash("Switched to Admin view.", "success") # Show success message
    # Redirect to the admin dashboard
    return redirect(url_for('admin_dashboard'))


# done by Khaw Pei Qi (StudentID: 243FC2456P)
# Route to switch from admin view back to normal user view
@app.route("/switch_to_user")
def switch_to_user():
    # Make sure the user is logged in
    if not current_user.is_authenticated:
        flash("You need to login first!", "danger") # Show error message
        return redirect(url_for('login')) # Redirect to login page

    session['as_admin'] = False # Turn off admin view for this session
    flash("Switched to User view.", "success") # Show confirmation message
    # Redirect to the main posts page
    return redirect(url_for('posts'))

# done by Khaw Pei Qi (StudentID: 243FC2456P)
# route to delete user
@app.route("/admin/delete_user/<string:email>", methods=["POST"])
@login_required
def delete_user(email):
    if current_user.role != "admin":
        abort(403)

    user = User.query.get_or_404(email)

    # Prevent admin self-delete
    if user.email == current_user.email:
        flash("You cannot delete your own admin account.", "danger")
        return redirect(url_for("admin_dashboard"))

    db.session.delete(user)
    db.session.commit()

    flash("User deleted successfully.", "success")
    return redirect(url_for("admin_dashboard"))


# Run app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_first_admin()
    app.run(debug=True)