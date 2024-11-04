import os
import base64
import pandas as pd
from typing import List, Optional, Tuple, Dict
from pydantic import BaseModel
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request
from dateutil import parser as date_parser
import logging
from bs4 import BeautifulSoup, Tag
import re
from urllib.parse import urlparse, urljoin

# Enhanced logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('unsubscribe_detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class UnsubscribeInfo(BaseModel):
    """Model for unsubscribe information"""
    found_in_header: bool = False
    found_in_html: bool = False
    header_link: Optional[str] = None
    html_link: Optional[str] = None
    context: Optional[str] = None
    confidence_score: float = 0.0

class EmailData(BaseModel):
    """Enhanced email data model"""
    id: str
    from_email: str
    from_domain: str
    date: str
    subject: str
    unsubscribe_info: UnsubscribeInfo
    raw_html: Optional[str] = None

class UnsubscribeLinkDetector:
    """Class for detecting unsubscribe links with advanced parsing"""
    
    def __init__(self):
        self.keywords = [
            'unsubscribe', 'opt-out', 'opt out', 'email preferences',
            'manage subscriptions', 'remove me', 'stop receiving',
            'cancel subscription', 'manage email', 'email settings'
        ]
        
        self.regex_patterns = [
            re.compile(r'unsubscribe', re.IGNORECASE),
            re.compile(r'opt[-\s]?out', re.IGNORECASE),
            re.compile(r'manage\s?(?:preferences|email|subscriptions)', re.IGNORECASE),
            re.compile(r'stop\s?receiving', re.IGNORECASE),
            re.compile(r'remove\s?(?:me|from)', re.IGNORECASE)
        ]
        
        self.context_tags = ['div', 'p', 'span', 'td', 'footer']

    def _get_link_context(self, element: Tag, max_length: int = 100) -> str:
        """Extract surrounding context of a link"""
        if not element:
            return ""
        
        # Get parent's text
        parent_text = " ".join(element.parent.stripped_strings)
        if len(parent_text) > max_length:
            parent_text = parent_text[:max_length] + "..."
        return parent_text.strip()

    def _calculate_confidence_score(self, link_element: Tag, link_url: str, context: str) -> float:
        """Calculate confidence score for unsubscribe link detection"""
        score = 0.0
        
        # Check link text
        link_text = link_element.get_text().lower()
        for keyword in self.keywords:
            if keyword in link_text:
                score += 0.4
                break
        
        # Check URL
        for keyword in self.keywords:
            if keyword in link_url.lower():
                score += 0.3
                break
        
        # Check context
        for keyword in self.keywords:
            if keyword in context.lower():
                score += 0.2
                break
        
        # Check for common unsubscribe URL patterns
        if re.search(r'(unsubscribe|opt-?out|preferences)', link_url, re.I):
            score += 0.1
        
        return min(score, 1.0)

    def find_unsubscribe_info(self, html_content: Optional[str], headers: Dict[str, str]) -> UnsubscribeInfo:
        """Find unsubscribe information in both headers and HTML content"""
        unsubscribe_info = UnsubscribeInfo()
        
        # Check List-Unsubscribe header
        header_link = headers.get('List-Unsubscribe', '')
        if header_link:
            unsubscribe_info.found_in_header = True
            # Extract URL from header (handling both mailto: and http(s):// links)
            matches = re.findall(r'<((?:https?|mailto):[^>]+)>', header_link)
            if matches:
                http_links = [link for link in matches if link.startswith('http')]
                if http_links:
                    unsubscribe_info.header_link = http_links[0]
                    unsubscribe_info.confidence_score = 0.9  # High confidence for header links
        
        # Parse HTML content if available
        if html_content:
            try:
                soup = BeautifulSoup(html_content, 'html.parser')
                best_link = None
                best_score = 0.0
                best_context = ""
                
                # Search for links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if not href or href.startswith('#'):
                        continue
                    
                    # Get context
                    context = self._get_link_context(link)
                    
                    # Calculate confidence score
                    score = self._calculate_confidence_score(link, href, context)
                    
                    if score > best_score:
                        best_score = score
                        best_link = href
                        best_context = context
                
                if best_link and best_score > 0.3:  # Minimum confidence threshold
                    unsubscribe_info.found_in_html = True
                    unsubscribe_info.html_link = best_link
                    unsubscribe_info.context = best_context
                    unsubscribe_info.confidence_score = max(
                        unsubscribe_info.confidence_score,
                        best_score
                    )
            
            except Exception as e:
                logger.warning(f"Error parsing HTML content: {e}")
        
        return unsubscribe_info

def authenticate_gmail():
    """Authenticate with Gmail API"""
    creds = None
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
    
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
    
    return build('gmail', 'v1', credentials=creds)

def extract_domain(email: str) -> str:
    """Extract domain from email address"""
    try:
        match = re.search(r'@([\w.-]+)', email)
        return match.group(1) if match else email
    except:
        return email

def fetch_emails(service, detector: UnsubscribeLinkDetector, max_results: int = 100) -> List[EmailData]:
    """Fetch emails with enhanced unsubscribe detection"""
    emails = []
    page_token = None

    try:
        while True:
            results = service.users().messages().list(
                userId='me',
                labelIds=['INBOX'],
                maxResults=min(max_results - len(emails), 100),
                pageToken=page_token
            ).execute()
            
            messages = results.get('messages', [])
            
            for msg in messages:
                try:
                    msg_data = service.users().messages().get(
                        userId='me',
                        id=msg['id'],
                        format='full'
                    ).execute()
                    
                    headers = {header['name']: header['value'] for header in msg_data['payload']['headers']}
                    
                    # Extract HTML content
                    html_content = None
                    if 'parts' in msg_data['payload']:
                        for part in msg_data['payload']['parts']:
                            if part['mimeType'] == 'text/html':
                                try:
                                    html_content = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                                except Exception as e:
                                    logger.warning(f"Error decoding HTML: {e}")
                                break
                    
                    # Get sender's email and domain
                    from_email = headers.get('From', '')
                    from_domain = extract_domain(from_email)
                    
                    # Detect unsubscribe information
                    unsubscribe_info = detector.find_unsubscribe_info(html_content, headers)
                    
                    # Create email data object
                    email = EmailData(
                        id=msg['id'],
                        from_email=from_email,
                        from_domain=from_domain,
                        date=headers.get('Date', ''),
                        subject=headers.get('Subject', ''),
                        unsubscribe_info=unsubscribe_info,
                        raw_html=html_content
                    )
                    
                    emails.append(email)
                    
                    # Log detection results
                    logger.info(f"Processed email from {from_domain}: "
                              f"Header link: {bool(unsubscribe_info.header_link)}, "
                              f"HTML link: {bool(unsubscribe_info.html_link)}, "
                              f"Confidence: {unsubscribe_info.confidence_score:.2f}")
                    
                except Exception as e:
                    logger.error(f"Error processing message {msg['id']}: {e}")
            
            if len(emails) >= max_results:
                break
                
            page_token = results.get('nextPageToken')
            if not page_token:
                break

        return emails

    except HttpError as error:
        logger.error(f"Error fetching emails: {error}")
        return []

def analyze_results(emails: List[EmailData]) -> pd.DataFrame:
    """Create detailed analysis of unsubscribe detection results"""
    analysis_data = []
    
    for email in emails:
        info = email.unsubscribe_info
        analysis_data.append({
            'domain': email.from_domain,
            'email': email.from_email,
            'subject': email.subject,
            'has_header_link': info.found_in_header,
            'has_html_link': info.found_in_html,
            'confidence_score': info.confidence_score,
            'unsubscribe_url': info.header_link or info.html_link,
            'context': info.context
        })
    
    df = pd.DataFrame(analysis_data)
    
    # Create domain-level summary
    domain_summary = (
        df.groupby('domain')
        .agg({
            'email': 'nunique',
            'has_header_link': 'mean',
            'has_html_link': 'mean',
            'confidence_score': 'mean',
            'unsubscribe_url': lambda x: x.iloc[0] if any(x.notna()) else None
        })
        .reset_index()
        .rename(columns={
            'email': 'unique_senders',
            'has_header_link': 'header_link_ratio',
            'has_html_link': 'html_link_ratio',
            'confidence_score': 'avg_confidence'
        })
        .sort_values('unique_senders', ascending=False)
    )
    
    return domain_summary

def main():
    """Main function to process emails and analyze unsubscribe capabilities"""
    try:
        # Initialize Gmail API and detector
        service = authenticate_gmail()
        detector = UnsubscribeLinkDetector()
        
        # Fetch and analyze emails
        emails = fetch_emails(service, detector, max_results=100)
        
        # Analyze results
        domain_summary = analyze_results(emails)
        
        # Save results
        domain_summary.to_csv('unsubscribe_analysis.csv', index=False)
        
        # Print summary
        print("\nDomain Analysis Results:")
        print(domain_summary)
        
        # Print overall statistics
        newsletter_domains = domain_summary[
            (domain_summary['header_link_ratio'] > 0) | 
            (domain_summary['html_link_ratio'] > 0)
        ]
        
        print(f"\nTotal domains analyzed: {len(domain_summary)}")
        print(f"Domains with unsubscribe links: {len(newsletter_domains)}")
        print(f"Average confidence score: {domain_summary['avg_confidence'].mean():.2f}")
        
    except Exception as e:
        logger.error(f"Error in main: {e}")
        raise

if __name__ == '__main__':
    main()
