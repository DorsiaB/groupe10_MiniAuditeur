from datetime import datetime
import os
from modules.recommendations import generate_recommendations


def generate_report(
    target,
    port_results,
    http_results=None,
    score=None,
    level=None
):
    """
    Génère un rapport Markdown d'audit.
    """

    # Création du dossier reports s'il n'existe pas
    os.makedirs("reports", exist_ok=True)

    # Création du nom du fichier avec la date/heure
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    filename = f"reports/audit_{timestamp}.md"


    with open(filename, "w", encoding="utf-8") as report:

        report.write("# Rapport MiniAuditeur\n\n")

        report.write(
            f"**Date de l'audit :** {timestamp}\n\n"
        )

        report.write(
            f"**Cible analysée :** {target}\n\n"
        )


        report.write("## Scan des ports TCP\n\n")


        open_ports = []

        filtered_ports = 0

        for result in port_results:
            if result["state"] == "OPEN":
                open_ports.append(result)

            elif result["state"] == "FILTERED":
                filtered_ports += 1


        report.write("### Ports ouverts\n\n")

        for port in open_ports:
            report.write(
                f"- Port {port['port']} : {port['state']}\n"
            )


        report.write("\n### Ports filtrés\n\n")

        report.write(
            f"{filtered_ports} ports filtrés.\n"
        )

        if http_results:

            report.write("\n## Analyse des en-têtes HTTP\n\n")
           
            recommendations = generate_recommendations(
                http_results,
                port_results
            )

            for header, value in http_results.items():
                report.write(
                    f"- {header} : {value}\n"
                )


            report.write(
                f"\n**Score sécurité : {score}/4**\n\n"
            )

            report.write(
                f"**Niveau : {level}**\n"
            )

            report.write("\n## Recommandations\n\n")

        for recommendation in recommendations:
            report.write(
                f"- {recommendation}\n"
            )

    return filename

if __name__ == "__main__":

    ports = [
        {"port": 22, "state": "OPEN"},
        {"port": 80, "state": "OPEN"}
    ]

    headers = {
        "Strict-Transport-Security": "Absent",
        "Content-Security-Policy": "Absent",
        "X-Frame-Options": "Absent",
        "X-Content-Type-Options": "Absent"
    }

    file = generate_report(
        "scanme.nmap.org",
        ports,
        headers,
        0,
        "Faible"
    )

    print(f"Rapport créé : {file}")