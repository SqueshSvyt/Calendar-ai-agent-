from flask import Flask, redirect, url_for, session
from dotenv import load_dotenv
from flasgger import Swagger, swag_from
from auth.auth import auth_bp

load_dotenv("keys.env")
app = Flask(__name__)
app.secret_key = 'aoWL15JEI1GKzEf9'

app.register_blueprint(auth_bp, url_prefix='/auth')

swagger = Swagger(app)


@app.route('/')
@swag_from({
    'responses': {
        302: {
            'description': 'Redirect to Google OAuth consent screen'
        }
    }
})
def home():
    if 'credentials' not in session:
        return redirect(url_for('auth.login'))

    return "You are logged in! Use /auth/list_events to fetch your Google Calendar events."


if __name__ == '__main__':
    app.run(debug=True)
