import requests
from urllib.parse import urlparse
import whois
import ssl
import socket
from datetime import datetime
from model import get_description

def analyze_website(url):
    """
    Analyze a website to determine if it might be a scam or official site.
    
    :param url: The URL of the website to analyze.
    """
    try:
        prompt = ""

        # Parse the URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        print()
        print(f"Analyzing website: {url}")
        print()
        prompt = prompt+f"Analyzing website: {url}"
        
        
        # -------------------------------------------------------------------------------------------------------------------------
        #=> [1]...> Check if the domain has a valid SSL certificate (Weight: 20%)
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            print("[+] SSL Certificate: Valid")
            prompt = prompt + "[+] SSL Certificate: Valid"
            
        except Exception as e:
            print("[-] SSL Certificate: Invalid or Missing")
            prompt = prompt + "[-] SSL Certificate: Invalid or Missing"



        # ---------------------------------------------------------------------------------------------------------------------------
        #=> [2]...>  Perform WHOIS lookup to check domain registration details (Weight: 15%)
        try:
            whois_info = whois.whois(domain)
            creation_date = whois_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            age_in_days = (datetime.now() - creation_date).days if creation_date else None
            
            if age_in_days and age_in_days < 365:
                print(f"[-] Domain Age: Less than 1 year old ({age_in_days} days)")
                prompt = prompt + f"[-] Domain Age: Less than 1 year old ({age_in_days} days)"
            elif age_in_days and age_in_days > 365:
                print(f"[+] Domain Age: Older than 1 year ({age_in_days} days)")
                prompt = prompt + f"[+] Domain Age: Older than 1 year ({age_in_days} days)"
            else:
                print(f"[+] Domain Age:{age_in_days} days found")
                prompt = prompt + f"[+] Domain Age:{age_in_days} days of age"
                
        except Exception as e:
            print(f"[-] WHOIS Lookup Failed: {e}")
            prompt = prompt + f"[-] WHOIS Lookup Failed: {e}"




        # ---------------------------------------------------------------------------------------------------------------------------
        #=> [3]...>  Check for suspicious keywords in the URL (Weight: 10%)
        suspicious_keywords = ["login", "secure", "account", "verify", "update", "bank"]
        if any(keyword in url.lower() for keyword in suspicious_keywords):
            print("[-] Suspicious Keywords Found in URL")
            prompt = prompt + "[-] Suspicious Keywords Found in URL"
        else:
            print("[+] No Suspicious Keywords in URL")
            prompt = prompt + "[+] No Suspicious Keywords in URL"




        # ---------------------------------------------------------------------------------------------------------------------------
        #=> [4]...>  Check if the domain is blacklisted using Google Safe Browsing API (Weight: 40%)
        google_safe_browsing_api_key = "AIzaSyCy9N2lZEE5zUAhsRJF3ecLWhwMNYmkBxI"
        if google_safe_browsing_api_key:
            safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={google_safe_browsing_api_key}"
            payload = {
                "client": {"clientId": "your-app-name", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            response = requests.post(safe_browsing_url, json=payload)
            if response.status_code == 200 and response.json().get("matches"):
                print("[-] Google Safe Browsing: This site is flagged as dangerous!")
                prompt = prompt + "[-] Google Safe Browsing: This site is flagged as dangerous!"
            else:
                print("[+] Google Safe Browsing: No threats detected.")
                prompt = prompt + "[+] Google Safe Browsing: No threats detected."

        else:
            print("[-] Google Safe Browsing Check Skipped (API Key Required)")
            prompt = prompt + "[-] Google Safe Browsing Check Skipped (API Key Required)"




        # ---------------------------------------------------------------------------------------------------------------------------
        #=> [5]...>  Check for HTTPS (Weight: 15%)
        if parsed_url.scheme == "https":
            print("[+] HTTPS: Enabled")
            prompt = prompt + "[+] HTTPS: Enabled"
            safety_score += 15  # Add 15 points for HTTPS
        else:
            print("[-] HTTPS: Not Enabled")
            prompt = prompt + "[-] HTTPS: Not Enabled"
            
            
            
        print()
        response = get_description(prompt)
        print("------------------------------------------------------------------------------------------------------------------------------------------------------------")
        print()
        print("                                                                              REPORT")
        print("                                                                            ----------")
        print()
        print(response)

    except Exception as e:
        print(f"Error during analysis: {e}")



# Get the URL from the terminal
if __name__ == "__main__":
    print()
    website_url = input("Enter the URL to analyze: ").strip()
    print()
    analyze_website(website_url)
    
    
    
    
    
    
    
    
    
    
    
    
    
    
# SSL Certificate Validation
# ~25%
# WHOIS Lookup
# ~15%
# Suspicious Keywords in URL
# ~12%
# Google Safe Browsing API
# ~45%
# HTTPS Check
# ~8%
# Total Confidence Estimate
# ~70-80%