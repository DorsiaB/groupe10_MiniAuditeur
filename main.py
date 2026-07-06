import argparse


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

    http_parser = subparsers.add_parser(
        "http",
        help="Analyser les en-têtes HTTP d'une URL"
    )

    http_parser.add_argument(
        "url",
        help="URL à analyser"
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
        print(f"Scan demandé sur : {args.target}")

    elif args.command == "http":
        print(f"Analyse HTTP demandée sur : {args.url}")

    elif args.command == "tls":
        print(f"Analyse TLS demandée sur : {args.domain}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()