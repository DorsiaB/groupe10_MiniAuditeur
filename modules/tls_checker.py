import ssl
import socket
from datetime import datetime

def tls_status(days_remaining):
    """
    Détermine le niveau d'état du certificat TLS.
    """

    if days_remaining <= 0:
        return "EXPIRE"

    elif days_remaining <= 7:
        return "CRITIQUE"

    elif days_remaining <= 30:
        return "ATTENTION"

    else:
        return "OK"


def check_tls(domain):
    """
    Vérifie le certificat TLS d'un domaine HTTPS.
    """

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=15
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

        status = tls_status(days_remaining)

        return {
            "valid": True,
            "expiration": expire_date.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining,
            "status": status
        }


    except socket.timeout:

        return {
            "valid": False,
            "error": "Délai d'attente dépassé lors de la connexion TLS."
        }


    except ConnectionRefusedError:

        return {
            "valid": False,
            "error": "Connexion TLS refusée par la cible."
        }


    except ssl.SSLError:

        return {
            "valid": False,
            "error": "Erreur lors de l'établissement de la connexion TLS."
        }


    except Exception:

        return {
            "valid": False,
            "error": "Impossible de vérifier le certificat TLS."
        }

