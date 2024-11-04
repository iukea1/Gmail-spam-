# Gmail Newsletter Analyzer

A Python tool that analyzes your Gmail inbox to identify newsletters and automated emails, detecting unsubscribe opportunities and providing insights into your email subscriptions.

## 🌟 Features

- **Automated Gmail Analysis**: Connects to your Gmail account securely using OAuth2
- **Newsletter Detection**: Identifies newsletter emails using multiple detection methods:
  - List-Unsubscribe headers
  - HTML content analysis
  - Contextual link detection
- **Smart Unsubscribe Detection**:
  - Finds unsubscribe links in email bodies
  - Detects unsubscribe headers
  - Provides confidence scoring for each detection
  - Preserves contextual information around unsubscribe links
- **Domain Analysis**:
  - Groups emails by sender domain
  - Tracks unique senders per domain
  - Calculates newsletter probability scores
- **Detailed Reporting**:
  - CSV export of findings
  - Domain-level statistics
  - Unsubscribe link aggregation

## 📋 Prerequisites

- Python 3.7+
- Gmail account
- Google Cloud Project with Gmail API enabled

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/gmail-newsletter-analyzer.git
cd gmail-newsletter-analyzer
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Set up Google Cloud Project:
   - Go to [Google Cloud Console](https://console.cloud.google.com)
   - Create a new project
   - Enable the Gmail API
   - Create OAuth 2.0 credentials
   - Download the credentials file as `credentials.json`

## ⚙️ Configuration

1. Place your `credentials.json` file in the project root directory
2. First run will open a browser window for Gmail authentication
3. After authentication, the app will save the token for future use

## 🚀 Usage

Run the main script:
```bash
python gmail_analyzer.py
```

This will:
1. Connect to your Gmail account
2. Analyze your recent emails
3. Generate reports in CSV format
4. Provide summary statistics in the console

## 📊 Output Files

The script generates several output files:

- `unsubscribe_analysis.csv`: Domain-level analysis with unsubscribe information
- `unsubscribe_detection.log`: Detailed logging of the analysis process

Example of the CSV output:
```csv
domain,unique_senders,header_link_ratio,html_link_ratio,avg_confidence,unsubscribe_url
newsletter.example.com,5,1.0,0.8,0.95,https://example.com/unsubscribe
```

## 🔍 Detection Methods

The tool uses multiple methods to identify newsletters and unsubscribe options:

1. **Header Detection**:
   - Looks for standard `List-Unsubscribe` headers
   - High confidence score for standard header implementations

2. **HTML Content Analysis**:
   - Searches for common unsubscribe link patterns
   - Analyzes link text and surrounding context
   - Uses BeautifulSoup for reliable HTML parsing

3. **Confidence Scoring**:
   - Scores each detection based on multiple factors:
     - Link text relevance
     - URL patterns
     - Surrounding context
     - Header presence
     - HTML structure

## 📊 Analysis Features

- **Domain Aggregation**: Groups emails by sender domain
- **Sender Analysis**: Tracks unique senders per domain
- **Link Detection**: Finds and validates unsubscribe links
- **Confidence Scoring**: Provides reliability metrics for detections
- **Context Preservation**: Saves surrounding text for verification

## 🛡️ Security

- Uses OAuth 2.0 for secure Gmail access
- Stores credentials securely
- Read-only access to your Gmail account
- No email content is stored permanently

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 Requirements

Create a `requirements.txt` file containing:
```
google-auth-oauthlib>=0.4.6
google-auth-httplib2>=0.1.0
google-api-python-client>=2.0.0
pandas>=1.3.0
pydantic>=1.8.0
beautifulsoup4>=4.9.3
python-dateutil>=2.8.2
```

## ⚠️ Limitations

- Only analyzes emails in your inbox (not other folders)
- Limited to recent emails (default: last 100)
- Requires manual verification of unsubscribe links
- May not detect all newsletter types
- Some unsubscribe links may require login

## 📄 License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## 🙏 Acknowledgments

- Google Gmail API Documentation
- BeautifulSoup4 Documentation
- Pandas Documentation
- Python Type Hints Documentation

## 🔄 Version History

- 1.0.0 (2024-03)
  - Initial release
  - Basic newsletter detection
  - Domain analysis
  - Unsubscribe link detection

## 📧 Contact

Your Name - [@yourusername](https://twitter.com/yourusername)

Project Link: [https://github.com/yourusername/gmail-newsletter-analyzer](https://github.com/yourusername/gmail-newsletter-analyzer)-
