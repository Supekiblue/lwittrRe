from smtp2go.core import Smtp2goClient
email_domain = 'domain here'
client = Smtp2goClient(api_key="token here")


def send_confirmation_link(username, email, url):

    payload = {
        "sender": f"lwittr@{email_domain}",
        "recipients": [email],
        "template_id": "2442926",
        "template_data": {
            "username": username,
            "url": url,
        }
    }

    response = client.send(**payload)

    if response.success:
        return response.json
    return False
