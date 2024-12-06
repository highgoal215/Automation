import os.path
import re
import base64
from email import policy
from email.parser import BytesParser
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def main():
    """Retrieve both sent and received messages and clean their bodies."""
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    try:
        service = build("gmail", "v1", credentials=creds)

        # Define your query for sent messages
        sender_email = "highgoal215@gmail.com"  # Replace with desired sender's email
        recipient_email = "snowwind0215@gmail.com"  # Replace with desired recipient's email
        start_date = "2024/12/01"  # Change this to your desired start date
        end_date = "2024/12/07"     # Change this to your desired end date
        
        # Query for both sent and received messages
        query_sent = f"from:{sender_email} after:{start_date} before:{end_date}"
        query_received = f"to:{recipient_email} after:{start_date} before:{end_date}"

        print("\nSent Messages:")
        retrieve_messages(service, query_sent)

        print("\nReceived Messages:")
        retrieve_messages(service, query_received)

    except HttpError as error:
        print(f"An error occurred: {error}")

def retrieve_messages(service, query):
    """Retrieve messages based on the provided query."""
    try:
        results = service.users().messages().list(userId="me", q=query).execute()
        messages = results.get("messages", [])

        if not messages:
            print("No messages found.")
            return
        
        # Handling pagination in case of many messages
        while True:
            for message in messages:
                msg = service.users().messages().get(userId="me", id=message['id']).execute()
                
                # Get the email body
                body = ""
                if 'payload' in msg and 'parts' in msg['payload']:
                    for part in msg['payload']['parts']:
                        if part['mimeType'] == 'text/plain':
                            body = part['body'].get('data', '')
                            break
                elif 'payload' in msg and 'body' in msg['payload']:
                    body = msg['payload']['body'].get('data', '')

                if body:
                    body = base64.urlsafe_b64decode(body).decode('utf-8')
                else:
                    body = "No content"
                
                # Clean the email content
                cleaned_content = clean_email_content(body)
                
                print(f"Cleaned Content: {cleaned_content[:100]}...")  # Print first 100 characters of cleaned content
            
            page_token = results.get('nextPageToken')
            if not page_token:
                break
            
            results = service.users().messages().list(userId="me", q=query, pageToken=page_token).execute()
            messages = results.get("messages", [])

    except HttpError as error:
        print(f"An error occurred: {error}")

def get_cleaned_body(msg):
    """Extract and clean the body of the email message."""
    # Decode the raw message
    raw_data = msg.get('body')
    if raw_data is None:
        # Handle the case where 'raw' is not available
        print("No raw data available for this message.")
        return None  # or some default value
    # Process raw_data as needed
    else:
    # raw_data = msg['raw']
        msg_bytes = base64.urlsafe_b64decode(raw_data.encode('UTF-8'))
        
        # Parse the email message
        mime_msg = BytesParser(policy=policy.default).parsebytes(msg_bytes)

        # Get the plain text part of the email body
        if mime_msg.is_multipart():
            for part in mime_msg.iter_parts():
                if part.get_content_type() == 'text/plain':
                    body = part.get_payload(decode=True).decode(part.get_content_charset())
                    break
        else:
            body = mime_msg.get_payload(decode=True).decode(mime_msg.get_content_charset())

        return clean_text(body)

def clean_email_content(content):
    # Remove email signatures
    content = re.sub(r'--\s*\n.*', '', content, flags=re.DOTALL)
    
    # Remove common disclaimer patterns
    content = re.sub(r'CONFIDENTIALITY NOTICE:.*', '', content, flags=re.DOTALL | re.IGNORECASE)
    content = re.sub(r'This email and any files transmitted with it are confidential.*', '', content, flags=re.DOTALL | re.IGNORECASE)
    
    # Remove special characters, keeping only alphanumeric characters, spaces, and basic punctuation
    content = re.sub(r'[^a-zA-Z0-9\s.,!?]', '', content)
    
    # Remove extra whitespace
    content = re.sub(r'\s+', ' ', content).strip()
    
    return content


if __name__ == "__main__":
    main()