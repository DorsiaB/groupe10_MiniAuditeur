import argparse
from modules.port_scanner import scan_ports
from modules.http_analyzer import analyze_headers, calculate_score, security_level
from modules.report_generator import generate_report
from modules.tls_checker import check_tls


def create_parser():
    parser = argparse.ArgumentParser(
        description="Mini auditeur de sécurité défensif"
    )

    subparsers = parser.add_subparsers(
        dest="command",
        help="Commande à exécuter"
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scanner les ports TCP d'une cible"
    )

    scan_parser.add_argument(
        "target",
        help="IP ou nom d'hôte à analyser"
    )

    scan_parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="Premier port à scanner"
    )

    scan_parser.add_argument(
        "--end",
        type=int,
        default=1024,
        help="Dernier port à scanner"
    )



    http_parser = subparsers.add_parser(
        "http",
        help="Analyser les en-têtes HTTP d'une URL"
    )

    http_parser.add_argument(
        "url",
        help="URL à analyser"
    )

    audit_parser = subparsers.add_parser(
        "audit",
        help="Lancer un audit complet"
    )

    audit_parser.add_argument(
        "target",
        help="Cible à auditer"
    )

    audit_parser.add_argument(
        "--start",
        type=int,
        default=1,
        help="Premier port"
    )

    audit_parser.add_argument(
        "--end",
        type=int,
        default=1024,
        help="Dernier port"
    )

    audit_parser.add_argument(
        "--url",
        help="URL HTTP à analyser"
    )

    tls_parser = subparsers.add_parser(
        "tls",
        help="Vérifier un certificat TLS"
    )

    tls_parser.add_argument(
        "domain",
        help="Domaine HTTPS à vérifier"
    )

    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()

    if args.command == "scan":
        print(f"Cible : {args.target}")
        print(f"Plage de ports : {args.start} - {args.end}")

        results = scan_ports(
            args.target,
            args.start,
            args.end
        )

        for result in results:
            if result["state"] == "OPEN":
                print(
                    f"Port {result['port']} : {result['state']}"
                )


    elif args.command == "http":
        print(f"Analyse HTTP demandée sur : {args.url}\n")

        headers = analyze_headers(args.url)

        if headers is None:
            print("Impossible d'analyser cette URL.")

        else:
            for header, value in headers.items():
                print(f"{header} : {value}")

            score = calculate_score(headers)

            level = security_level(score)

            print(f"\nScore de sécurité : {score}/4")
            print(f"Niveau : {level}")

    elif args.command == "audit":

        print(f"Audit complet de : {args.target}")

        ports = scan_ports(
            args.target,
            args.start,
            args.end
        )

        headers = None
        score = None
        level = None

        if args.url:
            headers = analyze_headers(args.url)

            if headers:
                score = calculate_score(headers)
                level = security_level(score)


        report = generate_report(
            args.target,
            ports,
            headers,
            score,
            level
        )

        print(f"\nRapport généré : {report}")
        
    elif args.command == "tls":

        print(f"Analyse TLS demandée sur : {args.domain}\n")

        result = check_tls(args.domain)

        if result["valid"]:

            print("Certificat valide : Oui")
            print(f"Expiration : {result['expiration']}")
            print(
                f"Jours restants : {result['days_remaining']}"
            )

        else:

            print("Certificat valide : Non")
            print(result["error"])

    else:
        parser.print_help()


if __name__ == "__main__":
    main()