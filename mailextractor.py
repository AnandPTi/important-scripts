import os.path
import re
import csv
import html
import base64
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
TEMPLATE_PHRASES = [
    "This is an automated response",
    "Do not reply to this email",
]

def authenticate_gmail():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
        print("Loaded credentials from token.json")
    else:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token_file:
            token_file.write(creds.to_json())
    return creds

def fetch_threads(service, max_results=500):
    threads = []
    request = service.users().threads().list(userId='me', maxResults=100)
    while request is not None and len(threads) < max_results:
        response = request.execute()
        threads.extend(response.get('threads', []))
        request = service.users().threads().list_next(request, response)
        print(f"Fetched {len(threads)} threads so far...")
    print(f"Total threads fetched: {len(threads)}")
    return threads[:max_results]

def is_template_reply(content):
    for phrase in TEMPLATE_PHRASES:
        if phrase.lower() in content.lower():
            return True
    return False

def decode_html_entities(text):
    """Decode HTML entities to plain text."""
    return html.unescape(text)

def get_email_body(message):
    """Extract the email body from the message payload."""
    def get_body_from_part(part):
        if part.get('mimeType') == 'text/plain':
            data = part.get('body', {}).get('data')
            if data:
                return base64.urlsafe_b64decode(data).decode('utf-8')
        elif part.get('mimeType') == 'text/html':
            data = part.get('body', {}).get('data')
            if data:
                # Convert HTML to plain text (basic conversion)
                html_text = base64.urlsafe_b64decode(data).decode('utf-8')
                # Remove HTML tags
                text = re.sub('<[^<]+?>', '', html_text)
                return decode_html_entities(text)
        elif part.get('parts'):
            for p in part['parts']:
                body = get_body_from_part(p)
                if body:
                    return body
        return None

    payload = message.get('payload', {})
    
    # First, try to get plain text content
    if payload.get('mimeType') == 'text/plain':
        data = payload.get('body', {}).get('data')
        if data:
            return base64.urlsafe_b64decode(data).decode('utf-8')
    
    # If not found, look through parts
    if payload.get('parts'):
        for part in payload['parts']:
            body = get_body_from_part(part)
            if body:
                return body
    
    # If still not found, try any available body data
    data = payload.get('body', {}).get('data')
    if data:
        return base64.urlsafe_b64decode(data).decode('utf-8')
    
    return None

def extract_query_response(service, thread_id, email_address):
    thread = service.users().threads().get(userId='me', id=thread_id, format='full').execute()
    messages = thread.get('messages', [])
    pairs = []
    query = None
    
    for msg in messages:
        headers = {header['name']: header['value'] for header in msg.get('payload', {}).get('headers', [])}
        sender = headers.get('From', '')
        
        # Get full message content instead of snippet
        body = get_email_body(msg)
        if not body:
            continue
            
        body = body.strip()
        
        if email_address not in sender:  # Incoming email
            query = body
        elif email_address in sender and query:  # Outgoing email responding to a query
            response = body
            if not is_template_reply(response):
                # Clean up the text
                query = re.sub(r'\s+', ' ', query).strip()
                response = re.sub(r'\s+', ' ', response).strip()
                pairs.append((query, response))
            query = None  # Reset query after pairing
            
    return pairs

def save_to_csv(data, filename="email_data.csv"):
    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Query", "Response"])  # Write headers
        for query, response in data:
            # Handle potential CSV injection
            writer.writerow([query, response])

def main():
    creds = authenticate_gmail()
    service = build('gmail', 'v1', credentials=creds)
    user_info = service.users().getProfile(userId='me').execute()
    print(f"Authenticated as: {user_info['emailAddress']}")
    
    support_email = "support@pompeii3.com"
    threads = fetch_threads(service, max_results=500)
    email_data = set()
    
    for thread in threads:
        if len(email_data) >= 100:  # Stop if 100 distinct pairs are collected
            break
        thread_id = thread['id']
        pairs = extract_query_response(service, thread_id, support_email)
        email_data.update(pairs)
    
    email_data = list(email_data)[:100]
    save_to_csv(email_data)
    print(f"Extracted data saved to email_data.csv with {len(email_data)} distinct pairs")

if __name__ == "__main__":
    main()