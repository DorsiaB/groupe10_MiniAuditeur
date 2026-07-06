import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(target, port):
    """
    Teste un port TCP sur une cible.

    Retourne :
    OPEN, CLOSED ou FILTERED
    """

    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(1)

        sock.connect((target, port))

        sock.close()

        return "OPEN"

    except ConnectionRefusedError:
        return "CLOSED"

    except TimeoutError:
        return "FILTERED"

    except socket.timeout:
        return "FILTERED"

    except OSError:
        return "FILTERED"

def scan_ports(target, start_port, end_port):
    """
    Scanne une plage de ports TCP avec plusieurs threads.
    """

    results = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = []

        for port in range(start_port, end_port + 1):
            future = executor.submit(
                scan_port,
                target,
                port
            )

            futures.append(
                (port, future)
            )

        for port, future in futures:
            state = future.result()

            results.append(
                {
                    "port": port,
                    "state": state
                }
            )

    return results

if __name__ == "__main__":
    results = scan_ports(
        "scanme.nmap.org",
        20,
        100
    )

    for result in results:
        print(
            f"Port {result['port']} : {result['state']}"
        )