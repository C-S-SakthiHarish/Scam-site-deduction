import openai
import os
from dotenv import load_dotenv

load_dotenv()


# prompt structuring
def get_description(req):
    try:
        # print("comming")
        prompt = """You are an AI cybersecurity analyst tasked with evaluating the safety and reliability of URLs based on the provided data. Analyze the following information for the given URLs and provide a detailed description of the website's safety, along with a calculated safety percentage. Use the following criteria for your analysis:

SSL Certificate: Check if the SSL certificate is valid or invalid/missing.

Domain Age: Evaluate the domain age (older domains are generally more trustworthy).

WHOIS Lookup: Assess the availability and legitimacy of the domain registration details.

Suspicious Keywords: Check if the URL contains any suspicious or malicious keywords.

Google Safe Browsing: Verify if the URL is flagged by Google Safe Browsing.

HTTPS: Confirm if the website uses HTTPS encryption.

For each URL, provide the following output:

Description => A detailed summary of the analysis, including observations about SSL, domain age, WHOIS lookup, suspicious keywords, Google Safe Browsing, and HTTPS.

Safety Percentage => A calculated percentage (0-100%) based on the above criteria, where 100% is completely safe and 0% is highly unsafe.

Recommendation => A final recommendation on whether the URL is safe to visit or not.

***Instructions***:

Analyze the provided data for each URL.

Follow the structure of the example outputs.

Provide a safety percentage based on the criteria.

Provide the  documentation based on the data.

Offer a clear recommendation based on the analysis.

***give the desclaimer that the url is not fully verified like content***
***The response should be like documentation with 500 words***
        """
        prompt_structure = [{"role": "assistant", "content": prompt},
                    {"role": "user", "content": f"{req}"}]
        response = ask_gpt(prompt_structure)
        return response
    except Exception as e:
        print({'error': str(e)})

    



# Function to send a request to GPT4 model AI
def ask_gpt(prompt):
    try:
        # Set your API key
        openai.api_key = os.getenv('APi_key')
        response = openai.ChatCompletion.create(
            model="gpt-4",  # Change to "gpt-3.5-turbo" if needed
            messages=prompt,
            temperature=0.7  # Adjust for more or less randomness
        )
        
        return response["choices"][0]["message"]["content"]
    except Exception as e:
        print({'error': str(e)})



























# pip install openai==0.28

# pip upgrade openai==1.0.0
# pip install openai==1.0.0


