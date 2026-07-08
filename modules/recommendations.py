def generate_recommendations(headers, ports, tls_results=None):
    """
    Génère des recommandations selon
    les résultats de l'audit.
    """

    recommendations = []

    if headers:

        if headers["Strict-Transport-Security"] == "Absent":
            recommendations.append(
                "Activer le header Strict-Transport-Security (HSTS)."
            )

        if headers["Content-Security-Policy"] == "Absent":
            recommendations.append(
                "Ajouter une Content-Security-Policy pour limiter les attaques XSS."
            )

        if headers["X-Frame-Options"] == "Absent":
            recommendations.append(
                "Ajouter X-Frame-Options pour réduire les risques de clickjacking."
            )

        if headers["X-Content-Type-Options"] == "Absent":
            recommendations.append(
                "Ajouter X-Content-Type-Options: nosniff."
            )


    for port in ports:

        if port["state"] == "OPEN":

            if port["port"] == 22:
                recommendations.append(
                    "Vérifier la configuration SSH : désactiver la connexion root et utiliser une authentification forte."
                )

            elif port["port"] == 80:
                recommendations.append(
                    "Le serveur HTTP est exposé. Vérifier la configuration web et privilégier HTTPS."
                )

            elif port["port"] == 25:
                recommendations.append(
                    "Vérifier la configuration SMTP afin d'éviter un relais ouvert."
                )
    if tls_results and tls_results.get("valid"):

        if tls_results["status"] == "ATTENTION":

            recommendations.append(
                "Le certificat TLS expire bientôt. Prévoir son renouvellement."
            )


        elif tls_results["status"] == "CRITIQUE":

            recommendations.append(
                "Le certificat TLS expire dans moins de 7 jours. Renouvellement urgent nécessaire."
            )


        elif tls_results["status"] == "EXPIRE":

            recommendations.append(
                "Le certificat TLS est expiré. Le remplacer immédiatement."
            )
    return recommendations