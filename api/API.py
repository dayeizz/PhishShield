import Utils
from urllib.parse import urlparse

# Returns score (0-100)


def get_prediction(url, model, oriUrl):
    if not urlparse(url).scheme:
        url = "https://" + url

    domain = urlparse(url).netloc
    if domain.startswith("www."):
        domain = domain[4:]

    output = {
        "SCORE": 100,
        "URL": url,
        "isGoogleSafePassed": True,
        "isdomainActive": True,
        "isSslCertified": True,
        "isntBlacklisted": True,
        "isntSusDomain": True,
        "isntUnshorten": True,
        "isntRedirected": True,
        "isLegit": None,
        "prediction": None,
        "probability": None,
        "age": None,
        "ipAddress": None,
        "location": None,
        "finalDomain": None,
        "whois": None,
    }


    # -----------------------------------------------------------------------------------

    # Retrieving check legitimacy of URL

    try:
        result = Utils.checkLegitimacy(url)

        if result["score"] != None:
            output["isLegit"] = {
                "score": result["score"],
                "domain": result["domain"]
            }
 
            if result["status"] == False:
                output["SCORE"] -= 20
                print("Deduct 20 for using almost similar top Domain")

    except Exception as e:
        print(f"Error occurred while checking legitimacy Domain: {e}")

    # -----------------------------------------------------------------------------------

    # Retrieving unshorten data

    try:
        result = Utils.unshortenUrl(url)

        # Check if URL was unshortened (changed)
        if result["final_url"] != oriUrl:
            output["isntUnshorten"] = False
            output["SCORE"] -= 5
            print("Deduct 5 for Using Shortening Services!")

        # Check for HTTP redirection
        if result["status"] == 300 <= result["status"] < 400:
            output["isntRedirected"] = False
            output["SCORE"] -= 30
            print("Deduct 30 for Redirect Status Code!")

    except:
        print("Not Using Shortening Services or Failed to Connect.")

    # -----------------------------------------------------------------------------------

    # Retrieving WHOIS data

    try:
        sus_domain = Utils.suspiciousDomain(url)
        if sus_domain == 1:
            output["isntSusDomain"] = False
            output["SCORE"] -= 10
    except:
        print("Error Occurred while finding Suspicious Domain!")

    # -----------------------------------------------------------------------------------

    # Retrieving age domain

    try:
        whois_data = Utils.whoisData(domain)
        if whois_data != None:
            age_str = whois_data.get("age")
            if age_str:
                try:
                    years = 0
                    months = 0

                    # Extracting years and months from the age string
                    age_parts = age_str.split()

                    # Parse years
                    if "year(s)" in age_parts:
                        years_index = age_parts.index("year(s)") - 1
                        years = float(age_parts[years_index])

                    # Parse months
                    if "month(s)" in age_parts:
                        months_index = age_parts.index("month(s)") - 1
                        months = float(age_parts[months_index])

                    age_in_months = (years * 12) + months
                    if age_in_months < 3:
                        output["whois"] = whois_data.get("data")
                        output["age"] = age_str
                        output["SCORE"] -= 40
                        print("Deduct 40 for Age less than 3 months!")
                    else:
                        output["age"] = age_str
                        output["whois"] = whois_data.get("data")
                except:
                    # Handle error in case age_str doesn't split as expected or conversion fails
                    print("An error occurred while retrieving age data")
            else:
                output["whois"] = whois_data.get("data")
    except:
        print("An error occurred while retrieving WHOIS data")

    # -----------------------------------------------------------------------------------

    # Retrieving final redirection domain

    try:
        final_urls = Utils.finalDomain(url)
        output["finalDomain"] = final_urls

    except:
        print("Error Occurred while retrieving the final domain name of the URL!")

    # -----------------------------------------------------------------------------------

    # Retrieving result from Google Safe Browsing

    try:
        if Utils.checkGoogleSafeBrowsing(url) != True:
            output["isGoogleSafePassed"] = False
            output["SCORE"] -= 40
            print("Deduct 40 Not Safe in Google!")

    except:
        print("Error Occurred while finding to google safe browsing!")

    # -----------------------------------------------------------------------------------

    # Retrieving result from DNS Blacklist

    try:
        if Utils.dnsBlacklist(domain) == True:
            output["isntBlacklisted"] = False
            output["SCORE"] -= 40
            print("Deduct 40 A DNS Blacklist!")

    except:
        print("Error Occurred while finding to domain DNS Blacklist!")

    # -----------------------------------------------------------------------------------

    # Retrieving result from Domain Active

    try:
        if Utils.domainActive(domain) != True:
            output["isdomainActive"] = False
            output["SCORE"] -= 30
            print("Deduct 30 Inactive Domain!")

    except:
        print("Error Occurred while finding to domain active!")

    # -----------------------------------------------------------------------------------

    # Retrieving result from SSL Certificate

    try:
        if Utils.sslCertificate(domain) != True:
            output["isSslCertified"] = False
            output["SCORE"] -= 20
            print("Deduct 20 Domain dont Have SSL Certifiate!")

    except:
        print("Error Occurred while finding SSL Certifiacate!")

    # -----------------------------------------------------------------------------------

    detail = Utils.ipAddressLocation(url)

    # Check if the IP address is available

    try:
        if detail["IP Address"] != None:
            output["ipAddress"] = detail["IP Address"]
        else:
            output["IP Address"] = False
            output["SCORE"] -= 40
            print("Deduct 40 Ip Address Not Found!")

    except:
        print("Error Occurred while finding IP address!")

    # Check if location is not available or is 'Not Available'

    try:
        if detail["location"] != None:
            output["location"] = detail["location"]
        else:
            output["location"] = False
            output["SCORE"] -= 10
            print("Deduct 10 Location Not Found!")

    except:
        print("Error Occurred while finding location!")

    # -----------------------------------------------------------------------------------

    # Make prediction using AI model
    ml = Utils.isURLMalicious(url, model)

    try:
        if ml["prediction"] != None:
            output["probability"] = ml["prob"]
            output["prediction"] = ml["prediction"]
            
            if ml["prediction"] == 1:
                output["SCORE"] -= 40
                print("Deduct 40: malicious link!")
        else:
            output["probability"] = ml["prob"]
            output["prediction"] = ml["prediction"]

    except Exception as e:
        print(f"Error occurred while ML prediction: {e}")

    # -----------------------------------------------------------------------------------
    return output
