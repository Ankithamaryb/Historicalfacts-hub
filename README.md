from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///new_database.db'  # Ensure this matches your SQLite file
app.config['SECRET_KEY'] = 'your_secret_key'

# Initializing Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model (Admin & User)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'user' or 'admin'

# Facts Model
class Fact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)

# Information Model
class Information(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)

# Quiz Model
class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(500), nullable=False)
    option1 = db.Column(db.String(255), nullable=False)
    option2 = db.Column(db.String(255), nullable=False)
    option3 = db.Column(db.String(255), nullable=False)
    option4 = db.Column(db.String(255), nullable=False)
    correct_answer = db.Column(db.String(255), nullable=False)

# Feedback Model
class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    message = db.Column(db.Text, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('login'))  # Redirect to login page

# Admin Dashboard Route
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('user_dashboard'))  # Prevent users from accessing admin
    return render_template('admin_dashboard.html')

# CRUD Operations for Admin
@app.route('/add_fact', methods=['POST'])
@login_required
def add_fact():
    if current_user.role == 'admin':
        title = request.form['title']
        description = request.form['description']
        new_fact = Fact(title=title, description=description)
        db.session.add(new_fact)
        db.session.commit()
        flash("Fact added successfully!", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_fact/<int:id>')
@login_required
def delete_fact(id):
    if current_user.role == 'admin':
        fact = Fact.query.get_or_404(id)
        db.session.delete(fact)
        db.session.commit()
        flash("Fact deleted successfully!", "danger")
    return redirect(url_for('admin_dashboard'))

@app.route('/add_quiz', methods=['POST'])
@login_required
def add_quiz():
    if current_user.role == 'admin':
        question = request.form['question']
        option1 = request.form['option1']
        option2 = request.form['option2']
        option3 = request.form['option3']
        option4 = request.form['option4']
        correct_answer = request.form['correct_answer']
        new_quiz = Quiz(question=question, option1=option1, option2=option2, option3=option3, option4=option4, correct_answer=correct_answer)
        db.session.add(new_quiz)
        db.session.commit()
        flash("Quiz added successfully!", "success")
    return redirect(url_for('admin_dashboard'))

# User Dashboard Route
@app.route('/user_dashboard')
@login_required
def user_dashboard():
    facts = Fact.query.all()  # Fetch all facts for users
    return render_template('user_dashboard.html', username=current_user.username, facts=facts)

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        new_user = User(username=username, password=password, role="user")
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful!", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin_dashboard' if user.role == "admin" else 'user_dashboard'))
        else:
            flash("Invalid username or password", "danger")

    return render_template('login.html')

# Logout Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully", "success")
    return redirect(url_for('login'))
# Admin: Manage Facts
@app.route('/manage_facts')
@login_required
def manage_facts():
    if current_user.role != "admin":
        return redirect(url_for('user_dashboard'))
    return "<h1>Manage Facts Page - Coming Soon!</h1>"

# Admin: Manage Information
@app.route('/manage_information')
@login_required
def manage_information():
    if current_user.role != "admin":
        return redirect(url_for('user_dashboard'))
    return "<h1>Manage Information Page - Coming Soon!</h1>"

# Admin: Manage Quiz
@app.route('/manage_quiz')
@login_required
def manage_quiz():
    if current_user.role != "admin":
        return redirect(url_for('user_dashboard'))
    return "<h1>Manage Quiz Page - Coming Soon!</h1>"

# Admin: View Feedback
@app.route('/manage_feedback')
@login_required
def manage_feedback():
    if current_user.role != "admin":
        return redirect(url_for('user_dashboard'))
    return "<h1>View Feedback Page - Coming Soon!</h1>"


# Ensure Admin Exists
def create_admin():
    admin = User.query.filter_by(username='admin123').first()
    if not admin:
        hashed_password = bcrypt.generate_password_hash('adminpass').decode('utf-8')
        admin = User(username='admin123', password=hashed_password, role='admin')
        db.session.add(admin)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin()  # Ensure an admin exists
    app.run(debug=True)
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='styles.css') }}">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">Welcome, {{ current_user.username }}</h1>
        
        <div class="list-group mt-4">
            <a href="{{ url_for('manage_facts') }}" class="list-group-item list-group-item-action">Manage Facts</a>
            <a href="{{ url_for('manage_information') }}" class="list-group-item list-group-item-action">Manage Information</a>
            <a href="{{ url_for('manage_quiz') }}" class="list-group-item list-group-item-action">Manage Quiz</a>
            <a href="{{ url_for('manage_feedback') }}" class="list-group-item list-group-item-action">View Feedback</a>
            <a href="{{ url_for('logout') }}" class="list-group-item list-group-item-action text-danger">Logout</a>
        </div>
    </div>
</body>
</html>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <style>
        body {
            background: url("{{ url_for('static', filename='background.jpg') }}") no-repeat center center fixed;
            background-size: cover;
        }
        .container {
            margin-top: 50px;
        }
        .card {
            background: rgba(255, 255, 255, 0.8);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1);
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">Historical Facts Hub</a>
            <div class="d-flex">
                <a href="{{ url_for('logout') }}" class="btn btn-danger">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container text-center">
        <div class="card p-4">
            <h2>Welcome, {{ username }}!</h2>
            <p>This is your dashboard. Explore historical facts and more.</p>

            <button class="btn btn-primary" onclick="showAlert()">Click Me</button>
        </div>
    </div>

    <script>
        function showAlert() {
            alert("Hello, welcome to the Historical Facts Hub!");
        }
    </script>
</body>
</html>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background: url("{{ url_for('static', filename='background.jpg') }}") no-repeat center center fixed;
            background-size: cover;
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .card {
            background: rgba(255, 255, 255, 0.8); /* Slight transparency */
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1);
        }
    </style>
</head>
<body>
    <div class="card p-4">
        <h2 class="text-center">Login</h2>
        <form method="POST">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" required>
            </div>
            <button type="submit" class="btn btn-primary w-100">Login</button>
        </form>
        <p class="mt-3 text-center">Don't have an account? <a href="{{ url_for('register') }}">Register</a></p>
    </div>
</body>
</html>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Register</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <h2 class="mt-5 text-center">Register</h2>
        <form method="POST">
            <div class="mb-3">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" name="username" required>
            </div>
            <div class="mb-3">
                <label for="email" class="form-label">Email</label>
                <input type="email" class="form-control" name="email" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" name="password" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Role</label>
                <select class="form-control" name="role" required>
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                </select>
            </div>
            <button type="submit" class="btn btn-primary w-100">Register</button>
        </form>
        <p class="mt-3 text-center">Already have an account? <a href="{{ url_for('login') }}">Login</a></p>
    </div>
</body>
</html>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="#">Historical Facts Hub</a>
            <div class="collapse navbar-collapse">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('facts') }}">Facts</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('information') }}">Information</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('quiz') }}">Quiz</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('feedback') }}">Feedback</a></li>
                    <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
                </ul>
            </div>
        </div>
    </nav>
    <div class="container mt-4">
        <h1>Welcome, {{ username }}</h1>
        <p>Select a section to explore:</p>
        <ul>
            <li><a href="{{ url_for('facts') }}">Facts</a></li>
            <li><a href="{{ url_for('information') }}">Information</a></li>
            <li><a href="{{ url_for('quiz') }}">Quiz</a></li>
            <li><a href="{{ url_for('feedback') }}">Feedback</a></li>
        </ul>
    </div>
</body>
</html>
