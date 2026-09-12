from dga_detector import detect_dga
from dns_tunnel_detector import detect_dns_tunnel
from alert_generator import create_alert


def test_dga_detection():

    print("\n" + "=" * 60)
    print("DGA DETECTION")
    print("=" * 60)

    domains = [
        "google",
        "ocymmekqogkw"
    ]

    for domain in domains:
        result = detect_dga(domain)
        alert = create_alert(result)

        print("\nResult:")
        print(alert)


def test_dns_tunnel_detection():

    print("\n" + "=" * 60)
    print("DNS TUNNELLING DETECTION")
    print("=" * 60)

    queries = [
        "www.google.com",
        "vaaaakardli.pirate.sea",
        "ce7e01cccd96c95965437b031e65fa8655.bot.hackbiji.top"
    ]

    for query in queries:
        result = detect_dns_tunnel(query)
        alert = create_alert(result)

        print("\nResult:")
        print(alert)


if __name__ == "__main__":

    print("AI CYBER THREAT DETECTION SYSTEM")

    test_dga_detection()
    test_dns_tunnel_detection()