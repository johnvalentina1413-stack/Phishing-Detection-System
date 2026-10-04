from url_analyzer import analyze_url
from email_analyzer import analyze_email


def print_header():
    print("\n" + "=" * 60)
    print("             PHISHING DETECTION SYSTEM")
    print("             URL & EMAIL ANALYSIS")
    print("=" * 60)


def display_result(result):
    print("\n" + "-" * 60)
    print("ANALYSIS RESULT")
    print("-" * 60)

    print(f"Risk Score    : {result['score']}/100")
    print(f"Risk Level    : {result['risk_level']}")
    print(f"Classification: {result['classification']}")

    print("\nDetected Indicators:")

    for index, indicator in enumerate(result["indicators"], start=1):
        print(f"  {index}. {indicator}")

    print("-" * 60)

    if result["classification"] == "Suspicious":
        print("⚠️  WARNING: This input may be associated with phishing.")
        print("    Do not enter passwords, OTPs, or financial information.")
    else:
        print("✅ No major phishing indicators were detected.")
        print("   However, always verify the source before trusting it.")

    print("-" * 60)


def analyze_url_input():
    print("\nURL ANALYSIS")
    print("Enter a URL to analyze.")
    print("Example: https://example.com")

    url = input("\nURL: ").strip()

    if not url:
        print("Please enter a URL.")
        return

    result = analyze_url(url)
    display_result(result)


def analyze_email_input():
    print("\nEMAIL ANALYSIS")
    print("Paste the email content below.")
    print("Type END on a new line when finished.")

    lines = []

    while True:
        line = input()

        if line.strip().upper() == "END":
            break

        lines.append(line)

    email_text = "\n".join(lines)

    if not email_text.strip():
        print("No email content provided.")
        return

    result = analyze_email(email_text)
    display_result(result)


def main():
    while True:
        print_header()

        print("\nChoose an option:")
        print("1. Analyze a URL")
        print("2. Analyze an Email")
        print("3. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            analyze_url_input()

        elif choice == "2":
            analyze_email_input()

        elif choice == "3":
            print("\nThank you for using the Phishing Detection System.")
            print("Stay safe online! 🔐")
            break

        else:
            print("\nInvalid choice. Please select 1, 2, or 3.")


if __name__ == "__main__":
    main()