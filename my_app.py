from flask import Flask, request, redirect, session
import pyotp

app = Flask(__name__)
app.secret_key = 'th3 supra secret passwd of an int3rn'

users = {
    'user@example.com': {
        'password': 'found the password',
        'otp_secret': pyotp.random_base32()
    }
}

@app.route('/')
def index():
    if 'user' in session:
        return redirect('/otp_verify')
    return render_template_string('''
        <h1>Login</h1>
        <form action="/login" method="post">
            <label>Email:</label>
            <input type="email" name="email" required><br>
            <label>Password:</label>
            <input type="password" name="password" required><br>
            <input type="submit" value="Login">
        </form>
    ''')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    user = users.get(email)
    
    if user and user['password'] == password:
        session['user'] = email
        return redirect('/otp_verify')
    return 'Invalid credentials', 403

@app.route('/otp_verify', methods=['GET', 'POST'])
def otp_verify():
    if 'user' not in session:
        return redirect('/')
    
    email = session['user']
    secret = users[email]['otp_secret']
    otp = pyotp.TOTP(secret)

    if request.method == 'POST':
        user_otp = request.form['otp']
        if otp.verify(user_otp):
            return 'Logged in successfully!'
        return 'Invalid OTP', 403

    return render_template_string('''
        <h1>2FA Verification</h1>
        <form action="/otp_verify" method="post">
            <label>Enter OTP:</label>
            <input type="text" name="otp" required><br>
            <input type="submit" value="Verify OTP">
        </form>
    ''')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
