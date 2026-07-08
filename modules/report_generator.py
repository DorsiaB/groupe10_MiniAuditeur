from datetime import datetime
import os
from modules.recommendations import generate_recommendations


def generate_report(
    target,
    port_results,
    http_results=None,
    score=None,
    level=None,
    tls_results=None
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

        report.write("## Résumé global du risque\n\n")

        open_ports_count = 0

        for result in port_results:
            if result["state"] == "OPEN":
                open_ports_count += 1


        risk_level = "Faible"

        if open_ports_count > 5:
            risk_level = "Moyen"

        if open_ports_count > 10:
            risk_level = "Élevé"

        report.write(
            f"- Niveau global du risque : {risk_level}\n"
        )
        
        report.write(
            f"- Ports ouverts détectés : {open_ports_count}\n"
        )

        if http_results:
            report.write(
                f"- Niveau de sécurité HTTP : {level}\n"
            )

        else:
            report.write(
                "- Analyse HTTP : indisponible\n"
            )

        if tls_results:

            if tls_results["valid"]:
                report.write(
                    "- Certificat TLS : valide\n"
                )

            else:
                report.write(
                    f"- Certificat TLS : erreur ({tls_results.get('error', 'inconnue')})\n"
                )

        report.write("\n")

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

        if tls_results:

            report.write(
                "\n## Analyse TLS\n\n"
            )

            if tls_results["valid"]:

                report.write(
                    "- Certificat : Valide\n"
                )

                report.write(
                    f"- Expiration : {tls_results['expiration']}\n"
                )

                report.write(
                    f"- Jours restants : {tls_results['days_remaining']}\n"
                )

                report.write(
                    f"- État : {tls_results['status']}\n"
                )

            else:

                report.write(
                    "- Certificat : Analyse impossible\n"
                )

                report.write(
                    f"- Erreur : {tls_results.get('error', 'Erreur inconnue')}\n"
                )
                
        if http_results:

            report.write(
                "\n## Analyse des en-têtes HTTP\n\n"
            )

            for header, value in http_results.items():

                report.write(
                    f"- {header} : {value}\n"
                )

            if score is not None:

                report.write(
                    f"\nScore sécurité : {score}/4\n"
                )

            if level:

                report.write(
                    f"Niveau : {level}\n"
                )

        else:

            report.write(
                "\n## Analyse des en-têtes HTTP\n\n"
            )

            report.write(
                "Analyse impossible : aucune donnée HTTP disponible.\n"
            )


        recommendations = generate_recommendations(
            http_results,
            port_results,
            tls_results
        )

        if recommendations:

            report.write(
                "\n## Recommandations\n\n"
            )

            for recommendation in recommendations:
                report.write(
                    f"- {recommendation}\n"
                )
    return filename