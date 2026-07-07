import ssl
import socket
from datetime import datetime


def check_tls(domain):
    """
    Vérifie le certificat TLS d'un domaine HTTPS.
    """

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as ssock:

                certificate = ssock.getpeercert()

        expire_date = datetime.strptime(
            certificate["notAfter"],
            "%b %d %H:%M:%S %Y %Z"
        )

        days_remaining = (
            expire_date - datetime.now()
        ).days

        return {
            "valid": True,
            "expiration": expire_date.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining
        }


    except Exception as e:

        return {
            "valid": False,
            "error": str(e)
        }

if __name__ == "__main__":

    result = check_tls("example.com")

    print(result)