import math
import socket
import re
import pydnsbl
from collections import Counter
import math
import requests
import whois
from datetime import datetime
from urllib.parse import urlparse, unquote
import validators
import tldextract
import idna
import Levenshtein
import csv

# ---------------------------------------------------------------------------------------

# Unshortening the URL function

def unshortenUrl(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        final_url = response.url

        response = requests.get(final_url, allow_redirects=True, timeout=5)
        status = response.status_code

        return {
            "final_url": response.url,
            "status": status
        }

    except requests.exceptions.RequestException as e:
        error_message = str(e)

        if "host='" in error_message:
            domain_name = error_message.split("host='")[1].split("'")[0]
            if not domain_name.startswith(("http://", "https://")):
                domain_name = "https://" + domain_name
            return {
                "final_url": domain_name,
                "status": None
            }
        else:
            print(f"[Error] Unshortening failed: {error_message}")
            return {
                "final_url": url,
                "status": None
            }

# ---------------------------------------------------------------------------------------

# Retrieve Domain Status Function

def domainStatus(url):
    try:
        if not urlparse(url).scheme:
            url = "https://" + url

        domain = urlparse(url).netloc
        if domain.startswith("www."):
            domain = domain[4:]

        whois_info = whois.whois(domain)

        return url if whois_info else False

    except Exception as e:
        return False

# ---------------------------------------------------------------------------------------

# Check URL is a DNS Blacklisted function

def dnsBlacklist(domain):
    try:
        domain_checker = pydnsbl.DNSBLDomainChecker()
        result = domain_checker.check(domain)

        return result.blacklisted
    except:
        return False

# ---------------------------------------------------------------------------------------

# Check Domain Active or Inactive function

def domainActive(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except:
        False

# ---------------------------------------------------------------------------------------

# Retreive Info of URL location and IP Address function

def ipAddressLocation(url):
    try:
        domain = urlparse(url).netloc

        ip = socket.gethostbyname(domain)
        geo = requests.get(f"http://ip-api.com/json/{ip}").json()
        location =(f"{geo['city']}, {geo['regionName']}, {geo['country']}")
        return {"IP Address": ip, 
                "location" : location
                }
    except:
        pass
# ---------------------------------------------------------------------------------------

# Detect using Non Standard Port function

def NonStdPort(url):
    try:
        if not urlparse(url).scheme:
            url = "https://" + url
     
        port = urlparse(url).netloc.split(":")
        if len(port) > 1:
            return 1
        return 0
    except:
        return 1

# ---------------------------------------------------------------------------------------

# Check info of URL function

def whoisData(domain):
    try:
        whois_info = whois.whois(domain)
        creation_date = whois_info.creation_date
        data = {}

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(creation_date, datetime):
            whois_info["creation_date"] = creation_date.strftime("%Y-%m-%d %H:%M:%S")

        if "updated_date" in whois_info:
            if isinstance(whois_info.updated_date, list):
                whois_info["updated_date"] = [
                    d.strftime("%Y-%m-%d %H:%M:%S") for d in whois_info.updated_date
                ]
            elif isinstance(whois_info.updated_date, datetime):
                whois_info["updated_date"] = whois_info.updated_date.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

        if "expiration_date" in whois_info:
            if isinstance(whois_info.expiration_date, list):
                whois_info["expiration_date"] = [
                    d.strftime("%Y-%m-%d %H:%M:%S") for d in whois_info.expiration_date
                ]
            elif isinstance(whois_info.expiration_date, datetime):
                whois_info["expiration_date"] = whois_info.expiration_date.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

        if creation_date is None:
            return None
        else:
            age = datetime.now() - creation_date
            years = age.days // 365
            months = (age.days % 365) // 30
            days = (age.days % 365) % 30
            age_str = f"{years} year(s) {months} month(s) {days} day(s)"

        for prop in whois_info:
            if isinstance(whois_info[prop], list):
                data[pascal_case(prop)] = ", ".join(whois_info[prop])
            else:
                data[pascal_case(prop)] = whois_info[prop]

        return {"age": age_str, "data": data}

    except Exception as e:
        print(f"Error whois_data: {e}")
        return None


def pascal_case(s):
    result = s.replace("_", " ").title()
    return result

# ---------------------------------------------------------------------------------------

# Check SSL Certificate function

def sslCertificate(domain):
    try:
        response = requests.get(f"https://ssl-checker.io/api/v1/check/{domain}")

        if response.status_code == 200:
            ssl_info = response.json()
            if ssl_info and "result" in ssl_info:
                result = ssl_info["result"]
                if "cert_valid" in result and result["cert_valid"]:
                    return True
                else:
                    return False
            else:
                return False
        else:
            return None
    except:
        False

# ---------------------------------------------------------------------------------------

# Using Google Safe Browsing API function

def checkGoogleSafeBrowsing(url):
    try:
        endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        params = {"key": "xxxxx"} # Input your API Key here
        payload = {
            "client": {"clientId": "YourClientID", "clientVersion": "1.5.2"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "THREAT_TYPE_UNSPECIFIED",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        response = requests.post(endpoint, params=params, json=payload)
        if response.status_code == 200:
            data = response.json()
            if "matches" in data:
                print("URL is considered a threat by Google Safe Browsing.")
                return False

            else:
                print("URL is not considered a threat by Google Safe Browsing.")
                return True

        else:
            pass
    except:
        pass

# ---------------------------------------------------------------------------------------

# Retrieve final domain of an URL function

def finalDomain(url):
    try:
        response = requests.get(url, allow_redirects=True)
        response.raise_for_status()

        final_url = response.url
        parsed_url = urlparse(final_url)
        domain = parsed_url.netloc
        if domain.startswith("www."):
            domain = domain[4:]
            return domain

        else:
            # If domain is empty, extract it from the URL
            return (
                url.replace("https://", "")
                .replace("http://", "")
                .replace("www.", "")
                .split("/")[0]
            )

    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL: {e}")
        return (
            url.replace("https://", "")
            .replace("http://", "")
            .replace("www.", "")
            .split("/")[0]
        )

# ---------------------------------------------------------------------------------------

# Calculate similarity of an URL with Top Million Domain function

def calculateSimilarity(url1, url2, scale=10):
    """Compute normalized Levenshtein similarity between two URLs."""
    if not url1 or not url2:
        return 0
    distance = Levenshtein.distance(url1, url2)
    return (1 - distance / max(len(url1), len(url2))) * scale

def stripUrl(url):
    """Extract domain name from URL, removing 'www.' if present."""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.strip("/")
    return domain.lstrip("www.")

def checkLegitimacy(fake_url, threshold=8.0):
    """Return a dictionary with score, status, matched domain, and message."""
    input_url = stripUrl(fake_url.lower())
    similar_domain = None

    try:
        with open('majestic_million.csv', 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                top_domain = row[0].lower().strip()

                if input_url == top_domain:
                    similar_domain = top_domain
                    return {
                        "score": 100, 
                        "status": True,
                        "domain": similar_domain
                    }

                score = calculateSimilarity(input_url, top_domain)
                if score >= threshold:
                    similar_domain = top_domain
                    return {
                        "score": round(score * 10, 2), 
                        "status": False,
                        "domain": similar_domain
                    }
            return {
                "score": 0, 
                "status": True,
                "domain": "No similar domain"
            }
    except Exception as e:
        print(f"[Error] Unable to read domain list: {e}")
        pass

# ------------------------------------------------------------------------------------------------------------------------------------

# Machine Learning Prediction 
def hasHttps(url):
    try:
        https = urlparse(url).scheme
        if 'https' in https:
            return 0
        return 1
    except:
        return 1


def validateUrl(url):
    try:
        if validators.url(url):
            return 0
        else:
            return 1
    except:
        return 1


def shannonEntropy(domain):
    char_counts = Counter(domain)
    total_chars = len(domain)
    
    char_probabilities = [count / total_chars for count in char_counts.values()]
    
    entropy = -sum(p * math.log2(p) for p in char_probabilities)
    
    return entropy


def domainEntropy(url):
    try: 
        domain = urlparse(url).netloc
        entropy = shannonEntropy(domain)
        if entropy >= 3.3:
            return 1
        else:
            return 0
    except:
        return 1
    
    
def shannonEntropy(url):
    char_counts = Counter(url)
    total_chars = len(url)
    char_probabilities = [count / total_chars for count in char_counts.values()]    
    entropy = -sum(p * math.log2(p) for p in char_probabilities)
    
    return entropy


def urlEntropy(url):
    try:
        entropy = shannonEntropy(url)
        return 1 if entropy >= 4.2 else 0
    except:
        return 1


def longUrl(url):
    try:
        return 1 if len(url) >= 48 else 0
    except:
        return 1


def longDomain(url):
    try:
        if not urlparse(url).scheme:
            url = "https://" + url
        domain = urlparse(url).netloc
        return 1 if len(domain) >= 17 else 0
    except:
        return 1    


def countDepth(url):
    try:
        matches = re.findall(r'/', url)
        return 1 if len(matches) >= 4 else 0
    except:
        return 1
    

def countDot(url):
    try:
        matches = len(re.findall(r"\.", url))
        return 1 if matches >= 3 else 0
    except:
        return 1    


def uppercaseUrl(url):
    try:
        if any(char.isupper() for char in url):
            return 1
        return 0
    except:
        return 1


def countDigitUrl(url):
    try:
        matches = re.findall(r"\d", url)
        return 1 if matches else 0
    except:
        return 1 
    

def countDigitDomain(url):
    try:
        if not urlparse(url).scheme:
            url = "https://" + url
        domain = urlparse(url).netloc
        matches = re.findall(r"\d", domain)
        return 1 if matches else 0
    except:
        return 1 


def hypenDomain(url):
    try:
        if not urlparse(url).scheme:
            url = "https://" + url
        domain = urlparse(url).netloc
        matches = re.findall(r'-', domain)
        return 1 if matches else 0
    except:
        return 1


def openRedirect(url):
    try:
        decoded = unquote(url)

        suspicious_domains = [
            r'[\x00\r\n<>\|\"#{}\[\]^~@` ]',                                   # Suspicious ASCII/control/symbols
            r'%09',                                                            # Horizontal tab
            r'%00|%0[dD]|%0[aA]',                                              # Null byte, CR, LF
            r'%2e%2e',                                                         # Encoded '..'
            r'\/\/{2,}',                                                       # Multiple slashes
            r'https?:[^/]{1}',                                                 # http: or https:
            r'(\\\\/)+',                                                       # Escaped slashes like \/ or \\//
            r'%2f',                                                            # Encoded forward slash '/'
            r'\\',                                                             # Backslash (escaped)
            r'%5c',                                                            # Encoded backslash
            r'javascript:',                                                    # JavaScript URI
            r'data:text/html;base64',                                          # Base64 data URI
            r'alert\s*\(',                                                     # alert( with optional space
            r'confirm\s*\(',                                                   # confirm( with optional space
            r'%E3%80%82',                                                      # Unicode full-width period (U+3002)
            r'\?.*http',                                                       # HTTP Parameter Pollution
            r'/http',                                                          # Folder as domain
            r'\?http',                                                         # disguised redirect
            r'data:text/html;base64,[A-Za-z0-9+/=]+',                          # Full base64 suspicious_domain
            r'[^\x00-\x7F]',                                                   # Non-ASCII characters
            r'%68%74%74%70',                                                   # Encoded 'http'
            r'\b\d{1,3}(?:\.\d{1,3}){3}\b',                                    # IPv4 address
            r'\b\d{8,10}\b',                                                   # Decimal-encoded IP
            r'([a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{1,4}',                       # IPv6 address
            r'\b0[0-7]+\.[0-7]+\.[0-7]+\.[0-7]+\b',                            # Octal
            r'\b0x[0-9a-fA-F]{8}\b',                                           # Full hex
            r'\b0x[0-9a-fA-F]+\.(?:0x[0-9a-fA-F]+\.){2}0x[0-9a-fA-F]+\b'       # Dot-separated hex
            r'javascript\s*:',                                                 # simple suspicious_domain
            r'java[\s%0a%0d]*script[\s%0a%0d]*:',                              # separated with CRLF/tab/space
            r'javascript\s*//',                                                # line comment based
            r'[\\\/%5c%2f]+javascript\s*:',                                    # /%5cjavascript: and similar
            r'j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:',                      # spaced letters
            r'(?i)<>\s*javascript:',                                           # <>javascript:
            r'javascrip[tT]\s*:',                                              # case variation
            r'%09.*javascript\s*:',                                            # tab then javascript
            r'javascript\s*:\s*(alert|prompt|confirm)\s*\(',                   # common XSS functions
            r'[^\w]javascript\s*:',                                            # preceding character like `/`, `;`, etc.
            r'x:1:///+%01*javascript\s*:',                                     # exotic pseudo-scheme
        ]

        redirect_keywords = [
            r"/redirect/", r"/cgi-bin/redirect\.cgi\?", r"/out/", r"/out\?",r"\?next=", 
            r"\?url=", r"\?target=", r"\?rurl=", r"\?dest=", r"\?destination=", r"\?redir=",
            r"\?redirect_uri=", r"\?redirect_url=", r"\?redirect=", r"\?view=", r"\?image_url=", 
            r"\?go=",r"\?return=", r"\?returnTo=", r"\?return_to=", r"\?checkout_url=", r"\?continue=", 
            r"\?return_path=",r"/login\?to=",r"success=", r"data=", r"login=", r"logout=", r"clickurl=",
            r"goto=", r"rit_url=", r"forward_url=", r"callback_url=",r"jump=", r"jump_url=", r"click\?u=", 
            r"originUrl=", r"origin=", r"Url=", r"desturl=", r"u=", r"u1=",r"page=", r"action=",
            r"action_url=", r"Redirect=", r"sp_url=", r"service=", r"recurl=", r"j\?url=", r"uri=",
            r"allinurl=", r"q=", r"link=", r"src=", r"tc\?src=", r"linkAddress=", r"location=", r"burl=",
            r"request=", r"backurl=", r"RedirectUrl=", r"ReturnUrl="
        ]

        for suspicious_domain in redirect_keywords + suspicious_domains:
            if re.search(suspicious_domain, decoded, re.IGNORECASE) or re.search(suspicious_domain, url, re.IGNORECASE):
                return 1
        return 0
    except:
        return 1


def suspiciousExtension(url):
    try:
        if not urlparse(url).scheme:
            url = "https://" + url
        parsed = urlparse(url)
        stripped = parsed.path + "?" + parsed.query if parsed.query else parsed.path
        malicious_extensions = (
            '.pdf', '.exe', '.dll', '.bat', '.cmd', '.scr', '.js', '.vb', '.vbs', '.msp', '.ps2', '.psc1', '.zip', 
            '.ps1', '.jar', '.py', '.rb', '.pif', '.rtf', '.vbe', '.docx', '.ps1xml', '.lnk', '.reg', '.sh','.bin',
            '.apk', '.msi', '.iso', '.doc', '.xsls', '.inf', '.ws', '.xls', '.jpeg', '.xlsm', '.ppt', '.html', '.htm',
            '.application', '.gadget', '.docm', '.jse', '.psc2', '.php', '.aspx', '.jsp', '.asp', '.cgi', '.mips',
            '.pl', '.wsf', '.class', '.sldm', '.war', '.ear', '.sys', '.cpl', '.drv', '.dmg', '.pkg', '.gif','.xhtml',
            '.mde', '.msc', '.xlam', '.ppam', '.mst', '.paf', '.scf', '.sct', '.shb', '.vxd', '.wsc', '.wsh', '.mpsl',
            '.txt', '.pptm', '.potm', '.msh', '.msh1', '.msh2', '.mshxml', '.mhs1xml', '.msh2xml', '.pol', '.hlp', 
            '.chm', '.rar', '.z', '.bz2', '.cab', '.gz', '.tar', '.ace', '.msu', '.ocx', '.feed','.ppc', '.arm', 
            '.phtml', '.stm', '.ppkg', '.bak', '.tmp', '.ost', '.pst', '.arm7', '.avi','.hta', '.shtml', '.sh4',
            '.img', '.vhd', '.vhdx', '.lock', '.lck', '.sln', '.cs', '.csproj', '.resx', '.config', '.snoopy',
            '.resources', '.pdb', '.manifest', '.mp3', '.wma', '.dot', '.wbk', '.xlt', '.xlm', '.arm6','.com',
            '.xla', '.pot', '.pps', '.ade', '.adp', '.mdb', '.cdb', '.mda', '.mdn', '.mdt', '.mdf', '.xml', 
            '.ldb', '.wps', '.xlsb', '.xll', '.xlw', '.m', '.jpg', '.css', '.-1', '.png', '.x86', '.spc'
        )
        suspicious_domain = re.compile(r"(" + "|".join(re.escape(ext) for ext in malicious_extensions) + r")(\?|$)", re.IGNORECASE)

        match = re.search(suspicious_domain, stripped)
        return 1 if match else 0
    except:
        return 1   


def suspiciousTld(url):
    try:
        suspicious_tlds = {
        "icu", "ml", "py", "tk", "xyz", "am", "bd", "best", "bid", "cd", "cfd", "cf", "click", "cyou", "date",
        "download", "faith", "ga", "gq", "help", "info", "ke", "loan", "men", "porn", "pw", "quest", "rest",
        "review", "sbs", "sex", "su", "support", "win", "ws", "xxx", "zip", "zw", "asia", "autos", "bar", "bio",
        "blue", "buzz", "casa", "cc", "charity", "club", "country", "dad", "degree", "earth", "email", "fit",
        "fund", "futbol", "fyi", "gdn", "gives", "gold", "guru", "haus", "homes", "id", "in", "ink", "jetzt",
        "kim", "lat", "life", "live", "lol", "ltd", "makeup", "mom", "monster", "mov", "ninja", "online", "pics",
        "plus", "pro", "pub", "racing", "realtor", "ren", "rip", "rocks", "rodeo", "run", "shop", "skin", "space",
        "tokyo", "uno", "vip", "wang", "wiki", "work", "world", "xin", "zone", "accountant", "accountants", "adult",
        "bet", "cam", "casino", "cm", "cn", "cricket", "ge", "il", "link", "lk", "me", "ng", "party", "pk", "poker",
        "ru", "sa", "science", "sexy", "site", "stream", "th", "tn", "top", "trade", "tube", "webcam", "wtf"
        }
        
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        domain_ascii = idna.encode(domain).decode('ascii')

        ext = tldextract.extract(domain_ascii)
        tld = ext.suffix.lower()
        if tld.startswith("xn--"):
            return 1
        return 1 if tld in suspicious_tlds else 0

    except:
        return 1  
   

def suspiciousWord(url):
    try:
        suspicious_words = [
            "index", "login", "wp-content", "images", "wp-includes", "js", "wp-admin", "component","wais",
            "home", "css", "plugins", "uploads", "dropbox", "html", "mozi", "themes", "view", "en","telnet",
            "admin", "ipfs", "secure", "site", "includes", "signin", "doc", "update", "alibaba","nntp",
            "products", "data", "file", "auth", "news", "modules", "document", "ii", "bins", "gopher",
            "components", "files", "content", "blog", "mailto", "myaccount", "gate", "img", "media",
            "dhl", "new", "app", "public", "user", "de", "d", "article", "a", "assets", "templates",
            "cp", "libraries", "bookmark", "default", "system", "mail", "web", "sejeal", "upload",
            "account", "detail", "index2", "openme", "info", "projects", "e", "category", "verify",
            "verification", "raw", "es", "db", "administrator", "log", "b", "personal", "prospero"
        ]

        suspicious_domain = r'\b(' + '|'.join(re.escape(word) for word in suspicious_words) + r')\b'

        match = re.search(suspicious_domain, url, re.IGNORECASE)
        return 1 if match else 0
    except:
        return 1


def suspiciousDomain(url):
    try:
        suspicious_domains = [
            "at.ua", "usa.cc", "baltazarpresentes.com.br", "pe.hu", "esy.es", "hol.es", "sweddy.com", "myjino.ru", "96.lt",
            "ow.ly", "clikar.com", "tinyurl.com", "bc.vc", "ity.im", "q.gs", "zytpirwai.net", "buff.ly", "bitly.is", "rb.gy",
            "chilp.it", "000webhostapp.com", "altervista.org", "awardspace.com", "biz.tc", "bravenet.com", "byethost.com",
            "freehosting.com", "freeservers.com", "heliohost.org", "hostinger.com", "infinityfree.net", "nfshost.com",
            "pages.jaiku.com", "scam.org", "uw.hu", "x10hosting.com", "zohosites.com", "s3.amazonaws.com", "site.90.cf",
            "webs.com", "tripod.com", "ipfs.io", "workers.dev", "profreehost.com", "livehost.fr", "hostfree.es", "claro.am",
            "freedynamicdns.org", "dottk.com", "zankyou.com", "freewebspace.com", "freeuk.com", "weebly.com", "geocities.com",
            "sitemix.jp", "ucoz.com", "8m.com", "00server.com", "000space.com", "t35.com", "pantheonsite.io", "wefreeweb.com",
            "brinkster.com", "50webs.com", "8k.com", "7li.ink", "fast2host.com", "000a.biz", "0fees.net", "abysales.com",
            "ietf.org", "weeblysite.com", "mixh.jp", "dweb.link", "1337x.to", "katcr.co", "kickass.to", "thepiratebay.org",
            "rarbg.to", "yify-torrents.com", "lemonparty.org", "goatse.cx", "meatspin.com", "tubgirl.com", "2girls1cup.info",
            "2girls1cup.tv", "mydeals.com", "graboid.com", "lifescams.com", "angelfire.com", "pastebin.com", "xsph.ru",
            "phishing.com", "malware.com", "scamalert.com", "square.site", "apbfiber.com", "sharepoint.com", "mxsimulator.com",
            "sogou.com", "clickbank.com", "myfavoritesites.com", "mysearch123.com", "herokuapp.com", "github.io", "freenom.com",
            "repl.co", "glitch.me", "netlify.app", "pastehtml.com", "surge.sh", "pages.dev", "fly.dev", "firebaseapp.com",
            "awsstatic.com", "azurewebsites.net", "vercel.app", "web.app", "appspot.com", "appchkr.com", "blogspot.com",
            "hostingerapp.com", "infomaniak.com", "myfreesites.net", "square7.ch", "wixsite.com","temp.domains/~",
            "zohosites.in", "squarespace.com", "blogger.com", "tumblr.com", "ghost.io", "strikingly.com", "jimdo.com",
            "webflow.io", "shopify.com", "bigcartel.com", "storenvy.com", "ecwid.com", "tictail.com", "gumroad.com",
            "sellfy.com", "fastspring.com", "sendowl.com", "paddle.com", "gumtree.com", "mozello.com", "ucraft.com",
            "carrd.co", "launchrock.com", "tilda.cc", "bubble.io", "instapage.com", "unbounce.com", "leadpages.com",
            "getresponse.com", "wordpress.com", "now.sh", "render.com", "glitch.com", "codepen.io", "sandboxd.io","/~",
            "jsfiddle.net", "codesandbox.io", "plunker.co", "scratch.mit.edu", "expo.io", "hyper.dev", "plnkr.co",
            "bitballoon.com", "itch.io", "scrimba.com", "stackblitz.com", "observablehq.com", "replit.com", "codeanywhere.com",
            "stacksity.com", "runkit.com", "xip.io", "nip.io", "vapor.cloud", "simmer.io", "glitchet.com", "felony.io",
            "deckdeckgo.com", "shynet.io", "fly.io", "updog.co", "nanoapp.io", "epizy.com", "trovalds.github.io", "netlify.com"
        ]
                
        shortening_domains = [
            "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly", "t.co", "tinyurl", "tr.im", "is.gd", "cli.gs",
            "yfrog.com", "migre.me", "ff.im", "tiny.cc", "url4.eu", "twit.ac", "su.pr", "twurl.nl", "snipurl.com", "short.to",
            "BudURL.com", "ping.fm", "post.ly", "Just.as", "bkite.com", "snipr.com", "fic.kr", "loopt.us", "doiop.com",
            "short.ie", "kl.am", "wp.me", "rubyurl.com", "om.ly", "to.ly", "bit.do", "lnkd.in", "db.tt", "qr.ae", "adf.ly",
            "bitly.com", "cur.lv", "ity.im", "q.gs", "po.st", "bc.vc", "twitthis.com", "u.to", "j.mp", "buzurl.com", "cutt.us",
            "u.bb", "yourls.org", "prettylinkpro.com", "scrnch.me", "filoops.info", "vzturl.com", "qr.net", "1url.com",
            "tweez.me", "v.gd", "link.zip.net", "shorturl.at", "rebrand.ly", "shorten.at", "shortenurl.at", "tiny.one",
            "tinyurl.one", "t2mio.com", "yep.it", "youtu.be", "zpr.io", "zurl.ws", "clck.ru", "cutt.ly", "shorturl.cm", "soo.gd",
            "tiny.vc", "tr.tt", "u.ii", "ur1.ca", "bit.li", "t2m.io", "clicky.me", "cr.yp.to", "owly.ai", "chilp.it", "snip.ly",
            "snurl.com", "poprl.com", "memurl.com", "trimurl.com", "zurl.co", "zzb.vc", "v.tc", "qr.cc", "t.it", "x.ee",
            "short.cm", "u.mavrev.com", "u.mytu.tu", "u.nu", "u.ddy.pr", "go.usa.gov", "miniurl.com", "corta.at", "sh.rt",
            "adcrun.ch", "surl.li", "rb.gy"
        ]

        shortening_services = r"\b(" + "|".join(re.escape(domain) for domain in shortening_domains) + r")\b"

        suspicious_domain = r'\b(' + '|'.join(re.escape(word) for word in suspicious_domains) + r')\b'

        if re.search(suspicious_domain, url, re.IGNORECASE) or re.search(shortening_services, url, re.IGNORECASE):
            return 1
        return 0
    except:
        return 1


def getInputArray(url):
    result = []
    result.append(domainEntropy(url))
    result.append(urlEntropy(url))
    result.append(longUrl(url))
    result.append(suspiciousExtension(url))
    result.append(countDepth(url))
    result.append(countDot(url))
    result.append(hasHttps(url))
    result.append(suspiciousTld(url))
    result.append(validateUrl(url))
    result.append(suspiciousWord(url))
    result.append(longDomain(url))
    result.append(hypenDomain(url))
    result.append(countDigitUrl(url))
    result.append(countDigitDomain(url))
    result.append(uppercaseUrl(url))
    result.append(suspiciousDomain(url))
    result.append(openRedirect(url))
    
    return result


def isURLMalicious(url, xgb):
    input = getInputArray(url)
    proba = xgb.predict_proba([input])[0][1]  # Probability of being malicious
    prediction = xgb.predict([input])[0]      # 0 = legitimate, 1 = malicious
    return {
        "prob": "{:.2f}".format(proba * 100),
        "prediction": int(prediction)
        }

