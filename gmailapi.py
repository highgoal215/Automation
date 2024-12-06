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
import pandas as pd
import json

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
emails_data = []
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
        
        # Initialize the list to collect email data
        print("Sent Messages:")
        retrieve_messages(service, query_sent)
        print("Received Messages:")
        retrieve_messages(service, query_received)
        # Load existing data from CSV
        df = pd.DataFrame(emails_data)
        if os.path.isfile("emails_for_training.csv"):
            # Load existing data from CSV
            existing_df = pd.read_csv('emails_for_training.csv')
            update_df=df[~df.apply(tuple, 1).isin(existing_df.apply(tuple,1))]
            update_df.to_csv('emails_for_training.csv', index=False,mode="a", header=False)
            print("update successfully!")
        else:
            df.to_csv('emails_for_training.csv', index=False, mode="a")
            print("Create CSV Files")
    
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
                
                # Extract metadata
                headers = msg['payload']['headers']
                metadata = extract_metadata(headers)
                # Get the email body
                body = get_email_body(msg)

                # Clean the email content
                cleaned_content = clean_email_content(body)
                 # Append data to emails_data list         
                emails_data.append({
                    'From': metadata['From'],
                    'To': metadata['To'],
                    'Subject': metadata['Subject'],
                    'Date': metadata['Date'],
                    'Cleaned Body': cleaned_content,
                })
            
                # Create a DataFrame from the collected email data
            
                # Display metadata and cleaned content
                # print(f"From: {metadata['From']}")
                # print(f"To: {metadata['To']}")
                # print(f"Subject: {metadata['Subject']}")
                # print(f"Date: {metadata['Date']}")
                # print(f"Cleaned Content: {cleaned_content[:100]}...")  # Print first 100 characters of cleaned content
            page_token = results.get('nextPageToken')
            if not page_token:
                break
            
            results = service.users().messages().list(userId="me", q=query, pageToken=page_token).execute()
            messages = results.get("messages", [])

    except HttpError as error:
        print(f"An error occurred: {error}")

def get_email_body(msg):
    """Extract the body of the email message."""
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
    
    return body

def extract_metadata(headers):
    """Extract relevant metadata from email headers."""
    metadata = {}
    for header in headers:
        name = header['name']
        value = header['value']
        if name in ['From', 'To', 'Subject', 'Date']:
            metadata[name] = value
    return metadata

def clean_email_content(content):
    """Clean the email content by removing signatures, disclaimers, and special characters."""
    
    # Remove email signatures
    content = re.sub(r'--\s*\n.*', '', content, flags=re.DOTALL)
    
    # Remove common disclaimer patterns
    content = re.sub(r'CONFIDENTIALITY NOTICE:.*', '', content, flags=re.DOTALL | re.IGNORECASE)
    
    # Remove special characters, keeping only alphanumeric characters, spaces, and basic punctuation
    content = re.sub(r'[^a-zA-Z0-9\s.,!?]', '', content)
    
    # Remove extra whitespace
    content = re.sub(r'\s+', ' ', content).strip()
    
    return content



if __name__ == "__main__":
    main()