import requests


SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]


def analyze_headers(url):
    """
    Analyse les en-têtes HTTP de sécurité d'une URL.
    """

    try:
        response = requests.get(
            url,
            timeout=5
        )

        headers = {}

        for header in SECURITY_HEADERS:
            headers[header] = response.headers.get(
                header,
                "Absent"
            )

        return headers

    except requests.exceptions.Timeout:
        print(
            "Erreur HTTP : délai d'attente dépassé."
        )
        return None

    except requests.exceptions.ConnectionError:
        print(
            "Erreur HTTP : impossible de joindre le serveur."
        )
        return None

    except requests.exceptions.RequestException:
        print(
            "Erreur HTTP : requête impossible."
        )
        return None

def calculate_score(headers):
    """
    Calcule un score de sécurité basé
    sur les headers présents.
    """

    score = 0

    for header, value in headers.items():
        if value != "Absent":
            score += 1

    return score

def security_level(score):
    """
    Retourne un niveau de sécurité
    selon le score obtenu.
    """

    if score == 4:
        return "Bon"

    elif score >= 2:
        return "Moyen"

    else:
        return "Faible"

if __name__ == "__main__":
    url = "https://example.com"

    headers = analyze_headers(url)

    if headers is None:
        print("Impossible d'analyser cette URL.")

    else:
        print(f"Analyse de : {url}\n")

        for header, value in headers.items():
            print(f"{header} : {value}")

        score = calculate_score(headers)

        level = security_level(score)

        print(f"\nScore de sécurité : {score}/4")
        print(f"Niveau : {level}")