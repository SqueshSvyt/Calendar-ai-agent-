import os
import pickle

from flasgger import swag_from
from flask import Blueprint, redirect, url_for, request, session, jsonify
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import google.auth

# Initialize the Blueprint for authentication-related routes
auth_bp = Blueprint('auth', __name__)

# Google OAuth 2.0 credentials
SCOPES = ['https://www.googleapis.com/auth/calendar']
CLIENT_SECRETS_FILE = './credentials.json'
TOKEN_FILE = '../token.json'


@auth_bp.route('/login')
@swag_from({
    'responses': {
        302: {
            'description': 'Redirect to Google OAuth consent screen'
        }
    }
})
def login():
    """Redirect the user to the Google OAuth 2.0 consent screen."""
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                CLIENT_SECRETS_FILE, SCOPES
            )
            creds = flow.run_local_server(port=0)

        with open("token.json", "w") as token:
            token.write(creds.to_json())

    flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)
    flow.redirect_uri = url_for('auth.oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )

    # Store the state in the session to verify the response later
    session['state'] = state

    return redirect(authorization_url)


@auth_bp.route('/oauth2callback')
def oauth2callback():
    """Handle the OAuth2 callback from Google."""
    if 'state' not in session:
        return "Session expired. Please log in again.", 400

    flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES, state=session['state'])
    flow.redirect_uri = url_for('auth.oauth2callback', _external=True)

    # Get authorization response from the request
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Save the credentials for future use
    credentials = flow.credentials
    with open(TOKEN_FILE, 'wb') as token:
        pickle.dump(credentials, token)

    session['credentials'] = credentials_to_dict(credentials)

    return redirect(url_for('home'))


# List Google Calendar events endpoint
@auth_bp.route('/list_events', methods=['GET'])
@swag_from({
    'responses': {
        200: {
            'description': 'List of events from Google Calendar',
            'examples': {
                'application/json': [
                    {"summary": "Meeting", "start": "2025-02-02T09:00:00Z", "end": "2025-02-02T10:00:00Z"}
                ]
            }
        },
        403: {
            'description': 'Authorization error'
        }
    }
})
def list_events():
    """Fetch the upcoming events from Google Calendar."""
    if 'credentials' not in session:
        return redirect(url_for('auth.login'))

    creds = session['credentials']
    if creds and creds.get('token') and creds.get('refresh_token'):
        credentials = google.auth.credentials.Credentials.from_authorized_user_info(creds)
        service = build('calendar', 'v3', credentials=credentials)

        events_result = service.events().list(
            calendarId='primary',
            maxResults=10,
            singleEvents=True,
            orderBy='startTime'
        ).execute()

        events = events_result.get('items', [])
        event_list = []
        for event in events:
            event_list.append({
                'summary': event['summary'],
                'start': event['start'],
                'end': event['end']
            })

        return jsonify(event_list)

    return "Authorization error. Please log in again.", 403


# Logout endpoint to revoke the user's session and delete credentials
@auth_bp.route('/logout')
@swag_from({
    'responses': {
        302: {
            'description': 'Redirect after logout'
        }
    }
})
def logout():
    """Revoke the user's access and delete the stored credentials."""
    if 'credentials' in session:
        session.pop('credentials')
        return redirect(url_for('home'))

    return redirect(url_for('auth.login'))


# Helper function to store credentials in session
def credentials_to_dict(credentials):
    """Converts credentials to a dictionary."""
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
