"""
Web scraping utilities for CyberFox.

This module provides functions for extracting text content from websites,
which can be used in dark web monitoring and data breach detection.
"""
import logging
import requests
import time
import random
from datetime import datetime
from typing import Optional, Tuple, Dict, List, Any, Union
from urllib.parse import urlparse

# Try importing trafilatura for web scraping, but provide a fallback if not available
try:
    import trafilatura
except ImportError:
    trafilatura = None

# Try importing BeautifulSoup as a fallback if trafilatura fails
try:
    from bs4 import BeautifulSoup
    BEAUTIFUL_SOUP_AVAILABLE = True
except ImportError:
    BEAUTIFUL_SOUP_AVAILABLE = False

logger = logging.getLogger(__name__)

def is_valid_url(url: str) -> bool:
    """
    Check if a URL is valid.
    
    Args:
        url: URL to check
        
    Returns:
        Boolean indicating if the URL is valid
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def get_random_user_agent() -> str:
    """
    Get a random user agent to avoid detection.
    
    Returns:
        A random user agent string
    """
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0"
    ]
    return random.choice(user_agents)

def create_session(proxies: Optional[Dict[str, str]] = None, 
                  tor_browser_profile: bool = False,
                  high_anonymity: bool = False) -> requests.Session:
    """
    Create a requests session with enhanced anonymity options.
    
    Args:
        proxies: Dictionary of proxy settings (e.g., {'http': 'socks5h://127.0.0.1:9050'})
        tor_browser_profile: Mimic the Tor Browser's profile for enhanced fingerprint protection
        high_anonymity: Apply additional anonymity settings for high-security operations
        
    Returns:
        Configured requests Session
    """
    session = requests.Session()
    
    # Set User-Agent based on anonymity preferences
    user_agent = get_random_user_agent()
    if tor_browser_profile:
        # Use Tor Browser's standard user agent
        user_agent = "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0"
    
    # Set default headers
    default_headers = {
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive'
    }
    
    if tor_browser_profile:
        # Tor Browser specific headers to prevent fingerprinting
        default_headers.update({
            'Accept-Language': 'en-US, en;q=0.9',
            'DNT': '1',  # Do Not Track
            # Avoid uncommon headers that could make the request stand out
        })
    else:
        default_headers.update({
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })
    
    # Apply headers
    session.headers.update(default_headers)
    
    # Set proxies if provided
    if proxies:
        session.proxies.update(proxies)
    
    # Additional anonymity settings
    if high_anonymity:
        # Disable persistent cookies
        session.cookies.clear()
        
        # Set additional anti-fingerprinting options
        if 'sec-ch-ua' not in session.headers:
            # Disable browser identification features (modern privacy enhancement)
            session.headers.update({
                'sec-ch-ua': '" Not A;Brand";v="99", "Chromium";v="96"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'none',
                'sec-fetch-user': '?1'
            })
    
    return session

def get_website_text_content(url: str, timeout: int = 30, 
                             session: Optional[requests.Session] = None,
                             retry_count: int = 3, 
                             retry_delay: int = 2,
                             tor_mode: bool = False,
                             save_raw_html: bool = False,
                             circuit_isolation: bool = False) -> Tuple[bool, Optional[str], Optional[Dict]]:
    """
    Get the main text content of a website with enhanced capabilities for dark web content.
    
    This function extracts the main text content using multiple strategies, with
    special handling for .onion sites and enhanced security for dark web monitoring.
    
    Args:
        url: URL of the website
        timeout: Timeout in seconds
        session: Optional requests Session to use (e.g., for Tor)
        retry_count: Number of times to retry on failure
        retry_delay: Delay between retries in seconds
        tor_mode: Whether to use special handling for .onion sites
        save_raw_html: Whether to save the raw HTML in the response metadata
        circuit_isolation: Whether to attempt to use a clean circuit for each request (Tor only)
        
    Returns:
        Tuple of (success, content, metadata)
    """
    metadata = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'extraction_method': None,
        'is_onion': '.onion' in url.lower(),
        'language': None,
        'html_size': 0,
        'text_size': 0,
        'status_code': None,
        'headers': None,
        'raw_html': None,
        'error': None
    }
    
    if not is_valid_url(url):
        logger.warning(f"Invalid URL: {url}")
        metadata['error'] = "Invalid URL format"
        return False, None, metadata
    
    # Create appropriate session based on URL type and parameters
    if session is None:
        # For .onion sites, always use Tor-specific settings
        if metadata['is_onion'] or tor_mode:
            # For .onion sites, we need a proper Tor SOCKS proxy
            tor_proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            
            # Set up a session with Tor Browser profile and high anonymity
            session = create_session(
                proxies=tor_proxies, 
                tor_browser_profile=True,
                high_anonymity=True
            )
            logger.debug(f"Created Tor session for {url}")
        else:
            # Regular session for clearnet sites
            session = create_session()
    
    # Initialize downloaded content
    downloaded = None
    response = None
    
    # Try to download with retries and security features
    for attempt in range(retry_count):
        try:
            # Circuit isolation: if enabled and Tor is being used, attempt to get new circuit
            if circuit_isolation and metadata['is_onion'] and attempt > 0:
                try:
                    # This is just a placeholder - the actual implementation would use stem
                    # to control the Tor process and create a new circuit
                    logger.debug(f"Attempting new Tor circuit for retry {attempt+1}")
                    # In a real implementation, you would use stem.control.Controller
                    # to send SIGNAL NEWNYM to the Tor process
                except Exception as circuit_error:
                    logger.warning(f"Failed to create new Tor circuit: {circuit_error}")
            
            # Use appropriate download method
            if trafilatura is not None and not metadata['is_onion']:
                # For clearnet sites, trafilatura works well
                # But for .onion sites, we need more control, so we skip this for those
                downloaded = trafilatura.fetch_url(url, timeout=timeout)
                
                if downloaded:
                    metadata['extraction_method'] = 'trafilatura_fetch'
            
            # If trafilatura failed or wasn't used, use direct requests
            if downloaded is None:
                # Add randomized delay for Tor requests to avoid pattern recognition
                if metadata['is_onion'] and attempt > 0:
                    jitter = random.uniform(0.5, 2.0)
                    time.sleep(retry_delay * jitter)
                
                response = session.get(url, timeout=timeout)
                response.raise_for_status()
                downloaded = response.text
                
                # Save response metadata
                metadata['status_code'] = response.status_code
                metadata['headers'] = dict(response.headers)
                metadata['html_size'] = len(downloaded)
                
                if save_raw_html:
                    metadata['raw_html'] = downloaded
                
                if downloaded:
                    metadata['extraction_method'] = 'requests'
            
            if downloaded:
                break
                
        except requests.exceptions.ConnectTimeout as e:
            err_msg = f"Connection timeout for {url}"
            if metadata['is_onion']:
                err_msg += " (This is common for Tor connections)"
            
            if attempt < retry_count - 1:
                logger.warning(f"{err_msg}. Retry {attempt+1}/{retry_count}")
                # Longer delay for Tor connections
                delay = retry_delay * (2 if metadata['is_onion'] else 1) * (1 + attempt)
                time.sleep(delay)
            else:
                logger.error(f"All download attempts timed out for {url}")
                metadata['error'] = "Connection timeout"
                return False, None, metadata
                
        except Exception as e:
            if attempt < retry_count - 1:
                logger.warning(f"Download attempt {attempt + 1} failed for {url}: {e}. Retrying...")
                time.sleep(retry_delay * (1 + attempt))  # Exponential backoff
            else:
                logger.error(f"All download attempts failed for {url}: {e}")
                metadata['error'] = str(e)
                return False, None, metadata
    
    if not downloaded:
        logger.warning(f"Failed to download content from {url}")
        metadata['error'] = "No content downloaded"
        return False, None, metadata
    
    # Extract content using available methods
    extracted_text = None
    
    # Try trafilatura first for best extraction
    if trafilatura is not None:
        try:
            extracted_text = trafilatura.extract(downloaded)
            if extracted_text:
                metadata['extraction_method'] = 'trafilatura_extract'
                metadata['text_size'] = len(extracted_text)
                
                # Detect language
                try:
                    metadata['language'] = detect_language(extracted_text)
                except Exception as lang_e:
                    logger.debug(f"Language detection failed: {lang_e}")
                
                logger.debug(f"Trafilatura successfully extracted {len(extracted_text)} bytes from {url}")
                return True, extracted_text, metadata
        except Exception as e:
            logger.warning(f"Trafilatura extraction failed for {url}: {e}")
    
    # Try BeautifulSoup as second option
    if BEAUTIFUL_SOUP_AVAILABLE and not extracted_text:
        try:
            soup = BeautifulSoup(downloaded, 'html.parser')
            
            # Remove script and style elements
            for script in soup(["script", "style", "meta", "noscript", "head", "footer", "nav"]):
                script.extract()
                
            # Get text and clean it
            extracted_text = soup.get_text(separator=' ')
            extracted_text = ' '.join(extracted_text.split())
            
            if extracted_text:
                metadata['extraction_method'] = 'beautifulsoup'
                metadata['text_size'] = len(extracted_text)
                
                # Detect language
                try:
                    metadata['language'] = detect_language(extracted_text)
                except Exception as lang_e:
                    logger.debug(f"Language detection failed: {lang_e}")
                
                logger.debug(f"BeautifulSoup successfully extracted {len(extracted_text)} bytes from {url}")
                return True, extracted_text, metadata
        except Exception as e:
            logger.warning(f"BeautifulSoup extraction failed for {url}: {e}")
    
    # Fall back to regex-based extraction
    if not extracted_text:
        try:
            # Use regex fallback method
            success, text = _fallback_get_website_content(url, timeout, session)
            if success and text:
                metadata['extraction_method'] = 'regex_fallback'
                metadata['text_size'] = len(text)
                
                # Detect language
                try:
                    metadata['language'] = detect_language(text)
                except Exception as lang_e:
                    logger.debug(f"Language detection failed: {lang_e}")
                
                logger.debug(f"Fallback method extracted {len(text)} bytes from {url}")
                return True, text, metadata
        except Exception as e:
            logger.error(f"All extraction methods failed for {url}: {e}")
            metadata['error'] = f"All extraction methods failed: {str(e)}"
            return False, None, metadata
    
    logger.warning(f"No text content could be extracted from {url}")
    metadata['error'] = "No text content could be extracted"
    return False, None, metadata

def _fallback_get_website_content(url: str, timeout: int = 30, 
                            session: Optional[requests.Session] = None) -> Tuple[bool, Optional[str]]:
    """
    Fallback method to get website content if trafilatura is not available.
    
    Args:
        url: URL of the website
        timeout: Timeout in seconds
        session: Optional requests Session to use
        
    Returns:
        Tuple of (success, content)
    """
    try:
        # Use the provided session or create a new one
        if session is None:
            session = create_session()
            
        # Send a request to the website
        response = session.get(url, timeout=timeout)
        response.raise_for_status()
        
        # Extract text content (very basic, not as good as trafilatura)
        content = response.text
        
        # Try to clean up HTML a bit (very basic)
        import re
        # Remove script tags and their content
        content = re.sub(r'<script[^>]*>.*?</script>', ' ', content, flags=re.DOTALL)
        # Remove style tags and their content
        content = re.sub(r'<style[^>]*>.*?</style>', ' ', content, flags=re.DOTALL)
        # Remove HTML tags
        content = re.sub(r'<[^>]*>', ' ', content)
        # Remove excessive whitespace
        content = re.sub(r'\s+', ' ', content).strip()
        
        return True, content
        
    except Exception as e:
        logger.error(f"Error getting content from {url} with fallback method: {e}")
        return False, None

def search_text_for_keywords(text: str, keywords: List[str]) -> List[str]:
    """
    Search text for specific keywords with improved context analysis.
    
    Args:
        text: Text to search
        keywords: List of keywords to search for
        
    Returns:
        List of found keywords
    """
    if not text or not keywords:
        return []
        
    # Convert text to lowercase for case-insensitive search
    text_lower = text.lower()
    
    # Search for each keyword
    found_keywords = []
    import re
    for keyword in keywords:
        keyword_lower = keyword.lower()
        
        # Simple contains check
        if keyword_lower in text_lower:
            found_keywords.append(keyword)
            continue
            
        # Check for word boundaries to avoid partial matches
        # For example, searching for "pass" shouldn't match "passport"
        pattern = r'\b' + re.escape(keyword_lower) + r'\b'
        if re.search(pattern, text_lower):
            found_keywords.append(keyword)
            continue
            
        # Check for phrases with small variations
        # For example, "credit card" should match "credit cards" or "credit-card"
        if ' ' in keyword_lower:
            # Create a pattern that allows for plural forms and hyphenation
            parts = keyword_lower.split()
            flexible_pattern = r'\b' + r'\W*'.join(re.escape(part) for part in parts) + r'\w{0,2}\b'
            if re.search(flexible_pattern, text_lower):
                found_keywords.append(keyword)
                
    return found_keywords

def extract_emails_from_text(text: str) -> List[str]:
    """
    Extract email addresses from text with improved pattern matching.
    
    Args:
        text: Text to extract emails from
        
    Returns:
        List of email addresses
    """
    if not text:
        return []
        
    import re
    
    # More comprehensive regex for email addresses
    # This pattern handles more edge cases while avoiding false positives
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    
    # Find all matches
    emails = re.findall(email_pattern, text)
    
    # Filter out some common false positives
    filtered_emails = []
    for email in emails:
        # Skip emails with very common fake domains often used in examples
        if any(fake_domain in email.lower() for fake_domain in ['@example.', '@test.', '@domain.']):
            continue
            
        # Skip very short local parts which are likely not real
        local_part = email.split('@')[0]
        if len(local_part) < 3:
            continue
            
        filtered_emails.append(email)
    
    # Remove duplicates and return
    return list(set(filtered_emails))

def extract_sensitive_data(text: str) -> Dict[str, List[str]]:
    """
    Extract various types of sensitive data from text.
    
    Args:
        text: Text to extract data from
        
    Returns:
        Dictionary with different types of sensitive data found
    """
    if not text:
        return {
            'emails': [],
            'credit_cards': [],
            'phone_numbers': [],
            'bitcoin_addresses': [],
            'ethereum_addresses': [],
            'monero_addresses': [],
            'ipv4_addresses': [],
            'ipv6_addresses': [],
            'ssn_numbers': [],
            'urls': [],
            'api_keys': [],
            'aws_keys': [],
            'private_keys': []
        }
    
    import re
    results = {}
    
    # Extract emails
    results['emails'] = extract_emails_from_text(text)
    
    # Extract potential credit card numbers with Luhn algorithm validation
    cc_pattern = r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
    cc_matches = re.findall(cc_pattern, text)
    results['credit_cards'] = []
    
    for cc in cc_matches:
        cc_digits = re.sub(r'[-\s]', '', cc)
        if is_valid_credit_card(cc_digits):
            results['credit_cards'].append(cc_digits)
    
    # Extract phone numbers (international format)
    phone_pattern = r'(?:\+\d{1,3}[-\s]?)?\(?\d{3}\)?[-\s]?\d{3}[-\s]?\d{4}'
    results['phone_numbers'] = re.findall(phone_pattern, text)
    
    # Extract Bitcoin addresses
    btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'
    results['bitcoin_addresses'] = re.findall(btc_pattern, text)
    
    # Extract Ethereum addresses
    eth_pattern = r'\b0x[a-fA-F0-9]{40}\b'
    results['ethereum_addresses'] = re.findall(eth_pattern, text)
    
    # Extract Monero addresses
    xmr_pattern = r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'
    results['monero_addresses'] = re.findall(xmr_pattern, text)
    
    # Extract IPv4 addresses
    ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    results['ipv4_addresses'] = re.findall(ipv4_pattern, text)
    
    # Extract IPv6 addresses
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b'
    results['ipv6_addresses'] = re.findall(ipv6_pattern, text)
    
    # Extract Social Security Numbers (US format)
    ssn_pattern = r'\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b'
    results['ssn_numbers'] = []
    
    # Validate SSN formats - exclude obviously invalid ones
    for ssn in re.findall(ssn_pattern, text):
        ssn_clean = re.sub(r'[^0-9]', '', ssn)
        # Skip all zeros, all nines, or starting with 000, 666, or 900-999
        if (ssn_clean != '000000000' and ssn_clean != '999999999' and
            not ssn_clean.startswith('000') and not ssn_clean.startswith('666') and
            not ssn_clean[0:3] in [str(i).zfill(3) for i in range(900, 1000)]):
            results['ssn_numbers'].append(ssn)
    
    # Extract URLs
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    results['urls'] = re.findall(url_pattern, text)
    
    # Extract potential API keys
    api_key_pattern = r'\b(?:[A-Za-z0-9+/]{32,}|[A-Za-z0-9_\-]{32,})\b'
    api_keys = re.findall(api_key_pattern, text)
    
    # Filter API keys to reduce false positives
    results['api_keys'] = [
        key for key in api_keys 
        if (any(c.islower() for c in key) and 
            any(c.isupper() for c in key) and 
            any(c.isdigit() for c in key))
    ]
    
    # Extract AWS keys (access key IDs)
    aws_key_pattern = r'\bAKIA[0-9A-Z]{16}\b'
    results['aws_keys'] = re.findall(aws_key_pattern, text)
    
    # Extract potential private keys
    private_key_pattern = r'-----BEGIN (?:RSA|DSA|EC|PGP) PRIVATE KEY-----[A-Za-z0-9\s/+=]+-----END (?:RSA|DSA|EC|PGP) PRIVATE KEY-----'
    results['private_keys'] = re.findall(private_key_pattern, text, re.DOTALL)
    
    return results

def is_valid_credit_card(cc_number: str) -> bool:
    """
    Validate a credit card number using the Luhn algorithm.
    
    Args:
        cc_number: Credit card number (digits only)
        
    Returns:
        Boolean indicating if the number passes the Luhn check
    """
    if not cc_number or not cc_number.isdigit():
        return False
        
    # Common credit card lengths
    if len(cc_number) not in [13, 15, 16, 19]:
        return False
    
    # Check for common test numbers
    test_numbers = ['4111111111111111', '5555555555554444', '378282246310005', 
                   '6011111111111117', '3530111333300000']
    if cc_number in test_numbers:
        return False
    
    # Apply Luhn algorithm
    sum_digits = 0
    num_digits = len(cc_number)
    odd_even = num_digits & 1
    
    for i in range(num_digits):
        digit = int(cc_number[i])
        
        if ((i & 1) ^ odd_even) == 0:
            digit *= 2
        if digit > 9:
            digit -= 9
            
        sum_digits += digit
    
    return (sum_digits % 10) == 0

def analyze_content_context(text: str, keywords: List[str], 
                          context_size: int = 75, 
                          max_snippets_per_keyword: int = 3,
                          sentiment_analysis: bool = True) -> Dict[str, Any]:
    """
    Advanced analysis of the context around found keywords for better threat understanding.
    
    This function analyzes the context around found keywords, estimates sentiment,
    identifies related entities, and provides valuable insights about the surrounding
    content to provide better threat assessment.
    
    Args:
        text: The text to analyze
        keywords: List of keywords to search for context
        context_size: Number of characters to include before and after each match
        max_snippets_per_keyword: Maximum number of context snippets per keyword
        sentiment_analysis: Whether to perform basic sentiment analysis on contexts
        
    Returns:
        Dictionary with comprehensive analysis results including:
        - context snippets for each keyword
        - sentiment analysis results
        - related entities found in context
        - proximity analysis between keywords
        - overall risk assessment based on context
    """
    if not text or not keywords:
        return {
            'keyword_contexts': {},
            'related_entities': [],
            'keyword_proximity': {},
            'sentiment': {},
            'overall_assessment': 'neutral',
            'risk_level': 'none',
            'nearby_sensitive_data': []
        }
    
    import re
    
    results = {
        'keyword_contexts': {},
        'related_entities': [],
        'keyword_proximity': {},
        'sentiment': {},
        'overall_assessment': 'neutral',
        'risk_level': 'none',
        'nearby_sensitive_data': []
    }
    
    text_lower = text.lower()
    
    # Get a list of all keyword matches with positions
    keyword_matches = []
    for keyword in keywords:
        keyword_lower = keyword.lower()
        
        # Use word boundary to match whole words only
        pattern = r'\b' + re.escape(keyword_lower) + r'\b'
        for match in re.finditer(pattern, text_lower):
            keyword_matches.append((keyword, match.start(), match.end()))
    
    # If no matches found, try a more lenient approach
    if not keyword_matches:
        for keyword in keywords:
            keyword_lower = keyword.lower()
            start = 0
            while start < len(text_lower):
                pos = text_lower.find(keyword_lower, start)
                if pos == -1:
                    break
                keyword_matches.append((keyword, pos, pos + len(keyword_lower)))
                start = pos + 1
    
    # Sort matches by position
    keyword_matches.sort(key=lambda x: x[1])
    
    # Extract context for each match
    for keyword, start, end in keyword_matches:
        if keyword not in results['keyword_contexts']:
            results['keyword_contexts'][keyword] = []
            
        # Skip if we already have enough snippets for this keyword
        if len(results['keyword_contexts'][keyword]) >= max_snippets_per_keyword:
            continue
        
        # Find sentence boundaries if possible
        sentence_start = max(0, text_lower.rfind('.', 0, start))
        if sentence_start == 0:
            sentence_start = max(0, text_lower.rfind('!', 0, start))
            if sentence_start == 0:
                sentence_start = max(0, text_lower.rfind('?', 0, start))
                
        sentence_end = text_lower.find('.', end)
        if sentence_end == -1:
            sentence_end = text_lower.find('!', end)
            if sentence_end == -1:
                sentence_end = text_lower.find('?', end)
                
        if sentence_end == -1:
            sentence_end = len(text)
        else:
            sentence_end += 1  # Include the punctuation
            
        # If the sentence is too long, fallback to fixed context size
        if sentence_end - sentence_start > context_size * 3:
            context_start = max(0, start - context_size)
            context_end = min(len(text), end + context_size)
        else:
            context_start = sentence_start
            context_end = sentence_end
        
        # Try to start and end at word boundaries
        while context_start > 0 and text[context_start].isalnum():
            context_start -= 1
        
        while context_end < len(text) - 1 and text[context_end].isalnum():
            context_end += 1
            
        context = text[context_start:context_end].strip()
        
        # Add ellipsis if we're not at text boundaries
        if context_start > 0:
            context = "..." + context
        if context_end < len(text):
            context = context + "..."
            
        # Highlight the keyword
        keyword_start = start - context_start
        keyword_end = end - context_start
        
        if 0 <= keyword_start < len(context) and 0 <= keyword_end <= len(context):
            highlighted = context[:keyword_start] + "**" + context[keyword_start:keyword_end] + "**" + context[keyword_end:]
            
            # Add context info with metadata
            context_obj = {
                'text': highlighted,
                'original': context,
                'position': start,
                'length': len(context)
            }
            
            # Basic sentiment analysis
            if sentiment_analysis:
                negative_words = ['illegal', 'threat', 'dangerous', 'criminal', 'unauthorized', 'stolen', 
                                 'malicious', 'harmful', 'suspicious', 'fraudulent', 'fake', 'attack',
                                 'exploit', 'breach', 'hack', 'crack', 'corrupt', 'dark', 'black',
                                 'illicit', 'underground', 'prohibited', 'restricted', 'undisclosed']
                
                positive_words = ['legal', 'authorized', 'secure', 'safe', 'legitimate', 'verified',
                                 'official', 'authentic', 'regulated', 'compliant', 'approved',
                                 'protected', 'registered', 'certified', 'validated']
                
                context_lower = context.lower()
                neg_count = sum(1 for word in negative_words if re.search(r'\b' + re.escape(word) + r'\b', context_lower))
                pos_count = sum(1 for word in positive_words if re.search(r'\b' + re.escape(word) + r'\b', context_lower))
                
                if neg_count > pos_count + 1:
                    sentiment = 'negative'
                elif pos_count > neg_count + 1:
                    sentiment = 'positive'
                else:
                    sentiment = 'neutral'
                    
                context_obj['sentiment'] = sentiment
                
                # More specific categorization
                if neg_count >= 3:
                    context_obj['risk_indicator'] = 'high'
                elif neg_count >= 1:
                    context_obj['risk_indicator'] = 'medium'
                else:
                    context_obj['risk_indicator'] = 'low'
            
            # Check for sensitive data in context
            sensitive_data_types = []
            
            # Simple check for credit card numbers
            if re.search(r'\b(?:\d{4}[-\s]?){3}\d{4}\b', context):
                sensitive_data_types.append('credit_card_number')
                
            # Check for emails
            if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', context):
                sensitive_data_types.append('email_address')
                
            # Check for cryptocurrency addresses
            if re.search(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b', context):
                sensitive_data_types.append('bitcoin_address')
                
            # Check for possible API keys
            if re.search(r'\b[A-Za-z0-9_\-]{20,40}\b', context):
                sensitive_data_types.append('possible_api_key')
                
            if sensitive_data_types:
                context_obj['sensitive_data'] = sensitive_data_types
                if context_obj.get('risk_indicator', 'low') != 'high':
                    context_obj['risk_indicator'] = 'medium'
                
                # Add to global list of sensitive data
                for data_type in sensitive_data_types:
                    if data_type not in results['nearby_sensitive_data']:
                        results['nearby_sensitive_data'].append(data_type)
            
            results['keyword_contexts'][keyword].append(context_obj)
    
    # Process keyword proximity analysis
    proximity_pairs = []
    for i in range(len(keyword_matches) - 1):
        kw1, start1, end1 = keyword_matches[i]
        kw2, start2, end2 = keyword_matches[i + 1]
        
        # If different keywords and close to each other
        if kw1 != kw2 and start2 - end1 < 200:
            proximity_pairs.append((kw1, kw2, start2 - end1))
    
    # Group proximity by keyword pairs
    for kw1, kw2, distance in proximity_pairs:
        pair = f"{kw1}_{kw2}"
        if pair not in results['keyword_proximity']:
            results['keyword_proximity'][pair] = []
        results['keyword_proximity'][pair].append(distance)
    
    # Calculate average distances
    for pair, distances in results['keyword_proximity'].items():
        results['keyword_proximity'][pair] = {
            'min_distance': min(distances),
            'avg_distance': sum(distances) / len(distances),
            'occurrences': len(distances)
        }
    
    # Analyze overall sentiment
    if sentiment_analysis:
        sentiments = {'positive': 0, 'neutral': 0, 'negative': 0}
        risk_indicators = {'high': 0, 'medium': 0, 'low': 0}
        
        for keyword, contexts in results['keyword_contexts'].items():
            keyword_sentiment = {'positive': 0, 'neutral': 0, 'negative': 0}
            
            for context in contexts:
                if 'sentiment' in context:
                    sentiments[context['sentiment']] += 1
                    keyword_sentiment[context['sentiment']] += 1
                if 'risk_indicator' in context:
                    risk_indicators[context['risk_indicator']] += 1
            
            # Determine dominant sentiment for this keyword
            if keyword_sentiment['negative'] > keyword_sentiment['positive']:
                results['sentiment'][keyword] = 'negative'
            elif keyword_sentiment['positive'] > keyword_sentiment['negative']:
                results['sentiment'][keyword] = 'positive'
            else:
                results['sentiment'][keyword] = 'neutral'
        
        # Overall assessment
        if sentiments['negative'] > sentiments['positive'] + sentiments['neutral']:
            results['overall_assessment'] = 'strongly negative'
        elif sentiments['negative'] > sentiments['positive']:
            results['overall_assessment'] = 'negative'
        elif sentiments['positive'] > sentiments['negative'] + sentiments['neutral']:
            results['overall_assessment'] = 'strongly positive'
        elif sentiments['positive'] > sentiments['negative']:
            results['overall_assessment'] = 'positive'
        else:
            results['overall_assessment'] = 'neutral'
        
        # Risk level assessment
        if risk_indicators['high'] >= 2:
            results['risk_level'] = 'high'
        elif risk_indicators['high'] == 1 or risk_indicators['medium'] >= 3:
            results['risk_level'] = 'medium'
        elif risk_indicators['medium'] > 0:
            results['risk_level'] = 'low'
        else:
            results['risk_level'] = 'minimal'
    
    # Find related entities and terms from context
    all_contexts = []
    for contexts in results['keyword_contexts'].values():
        all_contexts.extend([c['original'] for c in contexts])
    
    if all_contexts:
        combined_context = ' '.join(all_contexts)
        
        # Extract potential entities with simple NER-like patterns
        # Looking for capitalized terms that might be names, organizations, etc.
        entity_pattern = r'\b[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\b'
        potential_entities = re.findall(entity_pattern, combined_context)
        
        # Filter out common words that might be capitalized
        common_words = ['The', 'This', 'That', 'These', 'Those', 'There', 'Their', 'They', 'Then', 'And', 'But', 'Or', 'For', 'With']
        results['related_entities'] = [e for e in potential_entities if e not in common_words]
        
        # Deduplicate
        results['related_entities'] = list(set(results['related_entities']))
    
    return results

def detect_language(text: str) -> str:
    """
    Detect the language of a text.
    
    Args:
        text: Text to analyze
        
    Returns:
        ISO 639-1 language code or 'unknown'
    """
    if not text or len(text) < 10:
        return 'unknown'
    
    import re
    
    # Common language identifiers
    language_markers = {
        'en': ['the', 'and', 'of', 'to', 'in', 'is', 'you', 'that', 'it', 'he', 'for'],
        'ru': ['и', 'в', 'не', 'на', 'я', 'что', 'тот', 'быть', 'с', 'он', 'а'],
        'es': ['el', 'la', 'de', 'que', 'y', 'a', 'en', 'un', 'ser', 'se', 'no'],
        'fr': ['le', 'la', 'de', 'et', 'est', 'en', 'un', 'une', 'du', 'que', 'pas'],
        'de': ['der', 'die', 'das', 'und', 'ist', 'von', 'mit', 'den', 'ein', 'zu', 'für'],
        'zh': ['的', '一', '是', '在', '不', '了', '有', '和', '人', '这', '中'],
        'ar': ['ال', 'و', 'في', 'من', 'هو', 'على', 'ان', 'هذا', 'مع', 'أن', 'لا'],
    }
    
    # Count occurrences of markers
    text_lower = text.lower()
    text_words = re.findall(r'\b\w+\b', text_lower)
    
    scores = {}
    for lang, markers in language_markers.items():
        count = sum(text_words.count(marker) for marker in markers)
        scores[lang] = count
    
    # Return highest scoring language
    if not scores:
        return 'unknown'
    
    max_lang = max(scores.items(), key=lambda x: x[1])
    if max_lang[1] == 0:  # No markers found
        return 'unknown'
        
    return max_lang[0]

def filter_darkweb_content(text: str) -> Dict[str, Any]:
    """
    Analyze content for markers that suggest illegal/darkweb activities with advanced
    detection capabilities and contextual analysis.
    
    Args:
        text: Text to analyze
        
    Returns:
        Dictionary with detailed analysis results including threat scoring,
        risk assessment, and specific indicators found
    """
    if not text or len(text) < 50:
        return {
            'is_suspicious': False, 
            'categories': [], 
            'confidence': 0.0,
            'threat_level': 'NONE',
            'indicators': [],
            'risk_score': 0,
            'context_snippets': [],
            'sensitive_data_types': []
        }
    
    import re
    
    text_lower = text.lower()
    
    # Enhanced categories of suspicious content with relevant keywords
    categories = {
        'marketplace': [
            'marketplace', 'market', 'shop', 'store', 'vendor', 'escrow',
            'shipping', 'stealth', 'tracked', 'tracking', 'payment', 'pgp',
            'signature', 'verified', 'trusted', 'rating', 'reviews', 'price',
            'prices', 'cost', 'buy', 'sell', 'purchase', 'order', 'shipping',
            'domestic', 'international', 'product', 'products', 'quantity',
            'listing', 'listings', 'anonymous', 'hidden service', 'encrypted',
            'secure transaction', 'btc', 'xmr', 'crypto', 'finalize early'
        ],
        'drugs': [
            'mdma', 'lsd', 'cocaine', 'heroin', 'cannabis', 'marijuana', 'weed',
            'amphetamine', 'meth', 'methamphetamine', 'ketamine', 'pills',
            'pharmacy', 'prescription', 'medicine', 'recreational', 'dose', 
            'potent', 'pure', 'crystals', 'powder', 'smoke', 'high quality',
            'hydrocodone', 'oxycodone', 'opioid', 'benzo', 'xanax', 'valium',
            'psychedelic', 'mushrooms', 'psilocybin', 'microdose', 'blotter',
            'shard', 'rock', 'speed', 'molly', 'ecstasy', 'acid', 'tabs', 
            'prescription-free', 'no prescription', 'pharmaceutical grade',
            'lab tested', 'fentanyl', 'opium', 'kush', 'strain', 'controlled substance'
        ],
        'hacking': [
            'hack', 'hacker', 'hacking', 'exploit', 'vulnerability', 'zero-day',
            'malware', 'ransomware', 'botnet', 'ddos', 'phishing', 'tutorial',
            'backdoor', 'rootkit', 'keylogger', 'trojan', 'virus', 'worm',
            'spyware', 'cracking', 'breach', 'leaked', 'database', 'dump',
            'access', 'credentials', 'account', 'password', 'remote', 'server',
            'pentesting', 'pentest', 'sql injection', 'xss', 'cross-site',
            'shell', 'privilege escalation', 'rat', 'crypter', 'fud', 'bypass',
            'ssh', 'brute force', 'payload', 'mitm', 'reverse engineering',
            'decompile', 'disassembler', 'buffer overflow', 'obfuscated',
            'zero day', '0day', 'cybercrime', 'infect', 'encrypted comms'
        ],
        'financial_crime': [
            'carding', 'carder', 'cvv', 'fullz', 'dumps', 'transfer', 'bank drop',
            'cashout', 'money mule', 'western union', 'moneygram', 'paypal',
            'bitcoin', 'monero', 'cryptocurrency', 'wallet', 'mixing', 'tumbler',
            'washing', 'laundering', 'clone', 'skimmer', 'skimming', 'atm',
            'fraud', 'scam', 'counterfeit', 'fake', 'cash out', 'wire transfer',
            'swift', 'bank account', 'cc', 'credit card', 'prepaid', 'iban',
            'offshore', 'tax haven', 'shell company', 'identity theft',
            'synthetic id', 'socks', 'proxy', 'vpn', 'anonymous banking',
            'high balance', 'transfer limit', 'verification', 'kyc bypass'
        ],
        'weapons': [
            'gun', 'rifle', 'pistol', 'firearm', 'ammunition', 'ammo', 'weapon',
            'knife', 'explosive', 'handgun', 'shotgun', 'silencer', 'suppressor',
            'bullet', 'magazine', 'clip', 'rounds', 'barrel', 'revolver', 'semi-auto',
            'military grade', 'tactical', 'glock', 'ar15', 'ak47', 'assault',
            'combat', 'sniper', 'scope', 'unmarked', 'unregistered', 'serial number',
            'caliber', 'hollow point', 'armor piercing', 'body armor', 'bulletproof',
            'destructive device', 'grenade', 'detonator', 'trigger', 'smuggled'
        ],
        'identification': [
            'passport', 'license', 'identity', 'id card', 'driving license',
            'social security', 'birth certificate', 'document', 'citizenship',
            'resident', 'forgery', 'hologram', 'scan', 'biometric', 'photo id',
            'immigration', 'visa', 'green card', 'ssn', 'verified id',
            'national id', 'eu id', 'verification service', 'travel document',
            'government issued', 'face matching', 'background check', 'dob',
            'date of birth', 'address proof', 'utility bill', 'novelty id',
            'secondary id', 'government database', 'credit history'
        ],
        'human_trafficking': [
            'escort', 'service', 'companion', 'underage', 'young', 'minor',
            'trafficking', 'exploitation', 'forced', 'labor', 'services',
            'model', 'private room', 'massage', 'companion', 'discrete',
            'discreet', 'confidential', 'no questions', 'travel companion',
            'work visa', 'employment abroad', 'transportation provided',
            'accommodation provided', 'high income', 'cash payment'
        ]
    }
    
    # Additional signals that strongly indicate dark web content
    high_risk_indicators = [
        'tor hidden service', 'onion address', 'not indexed', 'no logs', 'no records',
        'untraceable', 'anonymous marketplace', 'bitcoin payment only', 'monero accepted',
        'no kyc', 'eliminating traces', 'leave no trail', 'encrypted market',
        'secure drop', 'dead drop', 'private listing', 'invite only', 'reference required',
        'verified vendor', 'trusted seller', 'forbidden', 'contraband', 'high-risk jurisdiction',
        'law enforcement', 'seizure', 'raid', 'legal disclaimer', 'at your own risk',
        'not for illegal use', 'darknet', 'black market', 'underground market',
        'not for use in', 'prohibited', 'restricted', 'illegal in most countries',
        'legal status varies', 'anonymity guaranteed', 'privacy focused', 'jurisdiction free'
    ]
    
    # Collect context snippets for detected terms
    context_snippets = []
    
    # Count matches in each category and find context
    results = {
        'matches': {}, 
        'categories': [], 
        'is_suspicious': False, 
        'confidence': 0.0,
        'threat_level': 'NONE',
        'indicators': [],
        'risk_score': 0,
        'context_snippets': [],
        'sensitive_data_types': []
    }
    
    total_matches = 0
    high_risk_count = 0
    
    # Check for high-risk indicators first
    for indicator in high_risk_indicators:
        if indicator in text_lower:
            matches = len(re.findall(r'\b' + re.escape(indicator) + r'\b', text_lower))
            if matches > 0:
                high_risk_count += matches
                results['indicators'].append(indicator)
                
                # Extract context snippet (50 chars before and after)
                for match in re.finditer(r'\b' + re.escape(indicator) + r'\b', text_lower):
                    start = max(0, match.start() - 50)
                    end = min(len(text), match.end() + 50)
                    context = text[start:end].replace('\n', ' ').strip()
                    context_snippets.append({
                        'term': indicator,
                        'category': 'high_risk',
                        'context': f"...{context}..."
                    })
    
    # Process categories
    for category, keywords in categories.items():
        category_matches = 0
        category_indicators = []
        
        for keyword in keywords:
            matches = len(re.findall(r'\b' + re.escape(keyword) + r'\b', text_lower))
            if matches > 0:
                category_matches += matches
                category_indicators.append(keyword)
                
                # Extract context for significant terms (only for the first few occurrences)
                for match_idx, match in enumerate(re.finditer(r'\b' + re.escape(keyword) + r'\b', text_lower)):
                    if match_idx >= 2:  # Limit to first 2 occurrences per term
                        break
                    start = max(0, match.start() - 50)
                    end = min(len(text), match.end() + 50)
                    context = text[start:end].replace('\n', ' ').strip()
                    context_snippets.append({
                        'term': keyword,
                        'category': category,
                        'context': f"...{context}..."
                    })
        
        results['matches'][category] = category_matches
        if category_indicators:
            results['indicators'].extend(category_indicators)
        total_matches += category_matches
    
    # Determine suspicious categories (at least 3 matches)
    suspicious_categories = []
    for category, matches in results['matches'].items():
        if matches >= 3:
            suspicious_categories.append(category)
    
    # Calculate risk score (0-100)
    if total_matches > 0 or high_risk_count > 0:
        # Base risk on matches
        base_risk = min(60, (total_matches * 2))
        
        # Add high risk indicators (each worth more)
        high_risk_value = min(30, high_risk_count * 6)
        
        # Add category diversity factor
        category_factor = min(10, len(suspicious_categories) * 3)
        
        # Calculate risk score
        risk_score = base_risk + high_risk_value + category_factor
        
        # Cap at 100
        risk_score = min(100, risk_score)
        
        # Determine threat level based on risk score
        if risk_score >= 75:
            threat_level = 'CRITICAL'
        elif risk_score >= 50:
            threat_level = 'HIGH'
        elif risk_score >= 25:
            threat_level = 'MEDIUM'
        elif risk_score > 0:
            threat_level = 'LOW'
        else:
            threat_level = 'NONE'
            
        # Calculate confidence (0.0-1.0)
        confidence = risk_score / 100
    else:
        risk_score = 0
        threat_level = 'NONE'
        confidence = 0.0
    
    # Check for sensitive data types that might be exposed
    sensitive_data = extract_sensitive_data(text)
    sensitive_data_types = [key for key, value in sensitive_data.items() if value]
    
    # Populate results
    results['is_suspicious'] = len(suspicious_categories) > 0 or high_risk_count > 0
    results['categories'] = suspicious_categories
    results['confidence'] = round(confidence, 2)
    results['threat_level'] = threat_level
    results['risk_score'] = round(risk_score)
    results['context_snippets'] = context_snippets[:10]  # Limit to top 10 snippets
    results['sensitive_data_types'] = sensitive_data_types
    
    return results