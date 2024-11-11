import os
import datetime
import time
import base64
import email
import shutil
from email import policy
from email.parser import BytesParser
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Define the Gmail API scope
SCOPES = ["https://mail.google.com/"]

# Base paths and files
BASE_PATH = "/Users/vikrantbhosale/Documents/backups/gmail"  # Adjust this path as needed
MONTH_LOG_FILE = os.path.join(BASE_PATH, "email_month_progress.log")  # Log for processed months
CHUNK_LOG_FILE = os.path.join(BASE_PATH, "email_chunk_progress.log")  # Log for processed chunks
SAVE_PATH = os.path.join(BASE_PATH, "emails")

# Rate limiting constants
MAX_WORKERS = 20        # Maximum number of worker threads
MAX_RETRIES = 5         # Maximum number of retries for rate limit errors

# Constants for dynamic adjustment
DAY_CHUNK_SIZE = 5      # Initial number of days per chunk (configurable)
MIN_DAY_CHUNK_SIZE = 1
MIN_MAX_WORKERS = 5
RATE_LIMIT_THRESHOLD = 5
COOLDOWN_PERIOD = 300   # Cooldown period in seconds (e.g., 5 minutes)
MAX_DAY_CHUNK_SIZE = 30
MAX_MAX_WORKERS = 20

# Global variables for rate limit tracking
rate_limit_errors = 0
last_rate_limit_time = None

def authenticate_gmail():
    """
    Authenticates the user and returns the Gmail credentials.
    """
    creds = None
    # Delete token.json to ensure fresh authentication
    if os.path.exists("token.json"):
        os.remove("token.json")
    # Check if token.json exists
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    # If there are no valid credentials, initiate the login flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # Run the OAuth flow to get new credentials
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for future runs
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds

def build_service(creds):
    """
    Builds a new Gmail service instance.
    """
    return build("gmail", "v1", credentials=creds)

def log_month_progress(year, month):
    """
    Logs the processed month to the month log file.
    """
    with open(MONTH_LOG_FILE, "a") as log_file:
        log_file.write(f"{year}/{month}\n")

def load_processed_months():
    """
    Loads the processed months from the month log file into a set.
    """
    processed_months = set()
    if os.path.exists(MONTH_LOG_FILE):
        with open(MONTH_LOG_FILE, "r") as log_file:
            entries = log_file.read().splitlines()
            processed_months.update(entries)
    return processed_months

def log_chunk_progress(year, month, chunk_start_day, chunk_end_day):
    """
    Logs the processed chunk to the chunk log file.
    """
    with open(CHUNK_LOG_FILE, "a") as log_file:
        log_file.write(f"{year}/{month}/{chunk_start_day}-{chunk_end_day}\n")

def load_processed_chunks():
    """
    Loads the processed chunks from the chunk log file into a set.
    """
    processed_chunks = set()
    if os.path.exists(CHUNK_LOG_FILE):
        with open(CHUNK_LOG_FILE, "r") as log_file:
            entries = log_file.read().splitlines()
            processed_chunks.update(entries)
    return processed_chunks

def sanitize_filename(filename, max_length=100):
    """
    Sanitizes a string to be used as a safe filename.
    """
    sanitized = ''.join(c for c in filename if c.isalnum() or c in (' ', '.', '_', '-')).rstrip()
    return sanitized[:max_length]

def prepare_email_data(email_message, msg_id):
    """
    Extracts and structures email data for buffering.
    """
    # Extract email components
    sender = email_message.get('From', 'unknown_sender')
    subject = email_message.get('Subject', 'no_subject')
    date_str = email_message.get('Date', '')
    content_parts = []
    attachments = []

    # Sanitize sender and subject to create a safe folder name
    safe_sender = sanitize_filename(sender, max_length=50)
    safe_subject = sanitize_filename(subject, max_length=50)

    # Parse the date
    try:
        parsed_date = email.utils.parsedate_to_datetime(date_str)
    except (TypeError, ValueError, IndexError):
        parsed_date = datetime.datetime.now()
    email_date_formatted = parsed_date.strftime('%Y%m%d_%H%M%S')

    # Generate email folder name with limited length
    email_folder_name = f"{email_date_formatted}_{safe_sender}_{msg_id}"
    if len(email_folder_name) > 100:
        # Use a hash to shorten the name
        hash_str = hashlib.md5(email_folder_name.encode()).hexdigest()
        email_folder_name = f"{email_date_formatted}_{hash_str}"

    # Extract email body and attachments
    if email_message.is_multipart():
        for part in email_message.walk():
            content_type = part.get_content_type()
            disposition = str(part.get('Content-Disposition') or '')
            if 'attachment' not in disposition.lower():
                if content_type in ['text/plain', 'text/html']:
                    charset = part.get_content_charset('utf-8') or 'utf-8'
                    content = part.get_payload(decode=True).decode(charset, errors='replace')
                    content_parts.append((content_type, content))
            else:
                attachment = extract_attachment(part)
                if attachment:
                    attachments.append(attachment)
    else:
        content_type = email_message.get_content_type()
        if content_type in ['text/plain', 'text/html']:
            charset = email_message.get_content_charset('utf-8') or 'utf-8'
            content = email_message.get_payload(decode=True).decode(charset, errors='replace')
            content_parts.append((content_type, content))

    # Extract headers
    headers = {header: value for header, value in email_message.items()}

    email_data = {
        'folder_name': email_folder_name,
        'sender': sender,
        'subject': subject,
        'date_str': date_str,
        'content_parts': content_parts,
        'attachments': attachments,
        'headers': headers
    }

    return email_data

def extract_attachment(part):
    """
    Extracts attachment data from a part.
    """
    filename = part.get_filename()
    if filename:
        filename = email.utils.collapse_rfc2231_value(filename)
        filename = sanitize_filename(filename)
        file_data = part.get_payload(decode=True)
        if file_data:
            return {'filename': filename, 'data': file_data}
        else:
            print(f"Attachment {filename} has no data or could not be decoded.")
    else:
        print("Found an attachment with no filename.")
    return None

def write_buffer_to_disk(email_buffer, folder_path):
    """
    Writes buffered emails to disk.
    """
    for email_data in email_buffer:
        email_folder_path = os.path.join(folder_path, email_data['folder_name'])
        os.makedirs(email_folder_path, exist_ok=True)

        # Save email body
        for content_type, content in email_data['content_parts']:
            if content_type == 'text/plain':
                filename = 'email.txt'
            elif content_type == 'text/html':
                filename = 'email.html'
            else:
                continue
            filepath = os.path.join(email_folder_path, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)

        # Save headers
        headers_filepath = os.path.join(email_folder_path, 'headers.txt')
        with open(headers_filepath, 'w', encoding='utf-8') as f:
            f.write(f"From: {email_data['sender']}\n")
            f.write(f"Date: {email_data['date_str']}\n")
            f.write(f"Subject: {email_data['subject']}\n")
            f.write("\nFull Headers:\n")
            for header, value in email_data['headers'].items():
                f.write(f"{header}: {value}\n")

        # Save attachments
        for attachment in email_data['attachments']:
            file_path = os.path.join(email_folder_path, attachment['filename'])
            with open(file_path, 'wb') as f:
                f.write(attachment['data'])
            print(f"Saved attachment: {file_path}")

def adjust_parallelization():
    """
    Adjusts the parallelization parameters when rate limiting occurs.
    """
    global rate_limit_errors, MAX_WORKERS, DAY_CHUNK_SIZE, last_rate_limit_time
    if rate_limit_errors >= RATE_LIMIT_THRESHOLD:
        if MAX_WORKERS > MIN_MAX_WORKERS:
            MAX_WORKERS = max(MIN_MAX_WORKERS, MAX_WORKERS // 2)
            print(f"Reduced MAX_WORKERS to {MAX_WORKERS} due to rate limiting.")
        if DAY_CHUNK_SIZE > MIN_DAY_CHUNK_SIZE:
            DAY_CHUNK_SIZE = max(MIN_DAY_CHUNK_SIZE, DAY_CHUNK_SIZE // 2)
            print(f"Reduced DAY_CHUNK_SIZE to {DAY_CHUNK_SIZE} due to rate limiting.")
        rate_limit_errors = 0
        last_rate_limit_time = time.time()

def increase_parallelization():
    """
    Increases the parallelization parameters after a cooldown period without rate limiting.
    """
    global MAX_WORKERS, DAY_CHUNK_SIZE, last_rate_limit_time
    if last_rate_limit_time:
        elapsed_time = time.time() - last_rate_limit_time
        if elapsed_time > COOLDOWN_PERIOD:
            if MAX_WORKERS < MAX_MAX_WORKERS:
                MAX_WORKERS = min(MAX_MAX_WORKERS, MAX_WORKERS * 2)
                print(f"Increased MAX_WORKERS to {MAX_WORKERS}.")
            if DAY_CHUNK_SIZE < MAX_DAY_CHUNK_SIZE:
                DAY_CHUNK_SIZE = min(MAX_DAY_CHUNK_SIZE, DAY_CHUNK_SIZE * 2)
                print(f"Increased DAY_CHUNK_SIZE to {DAY_CHUNK_SIZE}.")
            last_rate_limit_time = None

def process_email(creds, msg_id):
    """
    Processes a single email message and returns the data.
    """
    global rate_limit_errors
    service = build_service(creds)
    retry_count = 0
    while retry_count < MAX_RETRIES:
        try:
            # Fetch the email message
            message = service.users().messages().get(
                userId="me",
                id=msg_id,
                format='raw'  # Get the raw RFC 822 format
            ).execute()

            email_raw = base64.urlsafe_b64decode(message['raw'].encode('ASCII'))
            email_message = BytesParser(policy=policy.default).parsebytes(email_raw)

            email_data = prepare_email_data(email_message, msg_id)
            return email_data

        except HttpError as error:
            if error.resp.status == 429:  # Rate limit error
                retry_count += 1
                rate_limit_errors += 1
                adjust_parallelization()
                sleep_time = 2 ** retry_count
                print(f"Rate limit reached for email ID {msg_id}, retrying after {sleep_time} seconds...")
                time.sleep(sleep_time)
            else:
                print(f"Error downloading email ID {msg_id}: {error}")
                return None
        except Exception as e:
            print(f"Failed to process email ID {msg_id}: {e}")
            return None
    print(f"Exceeded retries for email ID {msg_id}. Skipping.")
    return None

def fetch_and_process_chunk(creds, query, folder_path, processed_chunk):
    """
    Fetches and processes emails for a given query (chunk).
    """
    service = build_service(creds)
    page_token = None
    all_message_ids = []

    while True:
        try:
            # Fetch emails with pagination
            results = service.users().messages().list(
                userId="me",
                q=query,
                pageToken=page_token,
                maxResults=500  # Increase batch size
            ).execute()
            messages = results.get("messages", [])

            if not messages:
                if not page_token:
                    print(f"No messages found for query: {query}")
                break

            # Collect message IDs
            all_message_ids.extend([msg["id"] for msg in messages])

            page_token = results.get("nextPageToken")
            if not page_token:
                break  # Exit the loop if there are no more pages

        except HttpError as error:
            print(f"Error fetching messages: {error}")
            if error.resp.status == 429:
                print("Rate limit reached, waiting before retrying...")
                time.sleep(10)
                continue

    if all_message_ids:
        # Process emails in parallel
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(process_email, creds, msg_id) for msg_id in all_message_ids]
            email_buffer = []
            buffer_limit = 100  # Adjust as needed

            for future in as_completed(futures):
                email_data = future.result()
                if email_data:
                    email_buffer.append(email_data)
                    print(f"Processed email: {email_data['folder_name']}")
                else:
                    print("Failed to process an email.")

                if len(email_buffer) >= buffer_limit:
                    write_buffer_to_disk(email_buffer, folder_path)
                    email_buffer.clear()

            # Write any remaining emails in the buffer
            if email_buffer:
                write_buffer_to_disk(email_buffer, folder_path)
                email_buffer.clear()

        # Log the processed chunk
        year, month, days = processed_chunk.split('/')
        chunk_start_day, chunk_end_day = days.split('-')
        log_chunk_progress(year, month, chunk_start_day, chunk_end_day)
    else:
        print(f"No emails found for query: {query}")
        # Even if no emails are found, log the chunk to avoid reprocessing
        year, month, days = processed_chunk.split('/')
        chunk_start_day, chunk_end_day = days.split('-')
        log_chunk_progress(year, month, chunk_start_day, chunk_end_day)

def check_emails_in_month(service, year, month, after_date_str, before_date_str):
    """
    Checks if there are any emails in the specified month.
    """
    query = f"after:{after_date_str} before:{before_date_str} -in:spam -in:trash"
    try:
        results = service.users().messages().list(
            userId="me",
            q=query,
            maxResults=1  # Only need to check if at least one email exists
        ).execute()
        messages = results.get("messages", [])
        if messages:
            return True
        else:
            return False
    except HttpError as error:
        print(f"Error checking emails for {year}/{month}: {error}")
        return False

def download_and_organize_emails(creds, cutoff_date_str, save_path="emails"):
    """
    Downloads emails before the specified cutoff date and organizes them by year and month.
    """
    global DAY_CHUNK_SIZE
    service = build_service(creds)
    cutoff_date = datetime.datetime.strptime(cutoff_date_str, "%m-%d-%Y")
    processed_months = load_processed_months()
    processed_chunks = load_processed_chunks()
    try:
        # Generate all months up to the cutoff date
        start_date = datetime.datetime(2000, 1, 1)  # Adjust as needed
        end_date = cutoff_date
        months = []
        current_date = start_date
        while current_date <= end_date:
            months.append((current_date.year, current_date.month))
            current_date += datetime.timedelta(days=32)
            current_date = current_date.replace(day=1)

        for year, month in months:
            month_key = f"{year}/{month}"
            if month_key in processed_months:
                print(f"Skipping {year}/{month} as it's already processed.")
                continue

            month_start = datetime.datetime(year, month, 1)
            if month == 12:
                next_month = datetime.datetime(year + 1, 1, 1)
            else:
                next_month = datetime.datetime(year, month + 1, 1)

            if next_month > cutoff_date:
                next_month = cutoff_date + datetime.timedelta(days=1)

            after_date_str = month_start.strftime('%Y/%m/%d')
            before_date_str = next_month.strftime('%Y/%m/%d')

            # Check if there are any emails in the month
            has_emails = check_emails_in_month(service, year, month, after_date_str, before_date_str)
            if not has_emails:
                print(f"No emails found for {year}/{month}. Marking month as processed.")
                log_month_progress(year, month)
                continue  # Skip to the next month

            folder_path = os.path.join(save_path, str(year), f"{month:02d}")
            os.makedirs(folder_path, exist_ok=True)

            # Split the month into day chunks
            day_chunks = []
            chunk_start = month_start
            while chunk_start < next_month:
                chunk_end = min(chunk_start + datetime.timedelta(days=DAY_CHUNK_SIZE), next_month)
                day_chunks.append((chunk_start, chunk_end))
                chunk_start = chunk_end

            print(f"Processing {len(day_chunks)} chunks for {year}/{month:02d}.")

            chunk_futures = []
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                for chunk_start, chunk_end in day_chunks:
                    chunk_start_day = chunk_start.day
                    chunk_end_day = (chunk_end - datetime.timedelta(days=1)).day

                    processed_chunk = f"{year}/{month}/{chunk_start_day}-{chunk_end_day}"
                    if processed_chunk in processed_chunks:
                        print(f"Skipping chunk: {processed_chunk} as it's already processed.")
                        continue

                    after_date_str = chunk_start.strftime('%Y/%m/%d')
                    before_date_str = chunk_end.strftime('%Y/%m/%d')
                    query = f"after:{after_date_str} before:{before_date_str} -in:spam -in:trash"

                    print(f"Submitting chunk: {after_date_str} to {before_date_str}")

                    chunk_future = executor.submit(
                        fetch_and_process_chunk, creds, query, folder_path, processed_chunk
                    )
                    chunk_futures.append(chunk_future)

                for future in as_completed(chunk_futures):
                    try:
                        future.result()
                    except Exception as e:
                        print(f"Error in chunk processing: {e}")

            # Compress the month's folder and remove uncompressed data
            compress_month_folder(save_path, year, month)
            # Log the month as processed
            log_month_progress(year, month)
            increase_parallelization()

    except HttpError as error:
        print(f"An error occurred: {error}")

def compress_month_folder(save_path, year, month):
    """
    Compresses the month's folder to save space.
    """
    folder_path = os.path.join(save_path, str(year), f"{month:02d}")
    if os.path.exists(folder_path):
        shutil.make_archive(folder_path, 'zip', folder_path)
        shutil.rmtree(folder_path)
        print(f"Compressed and removed folder: {folder_path}")

def delete_emails_before_date(creds, cutoff_date_str):
    """
    Deletes emails before the specified cutoff date.
    """
    service = build_service(creds)
    try:
        query = f"before:{cutoff_date_str} -in:spam -in:trash"
        page_token = None

        while True:
            results = service.users().messages().list(
                userId="me",
                q=query,
                pageToken=page_token,
                maxResults=500
            ).execute()
            messages = results.get("messages", [])

            if not messages:
                print(f"No more emails to delete before {cutoff_date_str}.")
                break

            message_ids = [msg["id"] for msg in messages]

            # Batch delete messages
            batch_request = {'ids': message_ids}
            try:
                service.users().messages().batchDelete(userId="me", body=batch_request).execute()
                print(f"Deleted {len(message_ids)} emails.")
            except HttpError as error:
                print(f"Error deleting emails: {error}")
                if error.resp.status == 429:
                    print("Rate limit reached, waiting before retrying...")
                    time.sleep(10)
                    continue

            page_token = results.get("nextPageToken")
            if not page_token:
                break

    except HttpError as error:
        print(f"An error occurred: {error}")

def main():
    """
    Main function to execute the script.
    """
    # Accept cutoff date from user in mm-dd-yyyy format
    cutoff_date_str = input("Enter the cutoff date (mm-dd-yyyy): ")
    creds = authenticate_gmail()

    # Download and organize emails
    download_and_organize_emails(creds, cutoff_date_str, save_path=SAVE_PATH)

    # Delete emails before the cutoff date
    delete_emails_before_date(creds, cutoff_date_str)

if __name__ == "__main__":
    main()