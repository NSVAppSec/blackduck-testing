import json
import argparse
import requests

from colorama import Fore, Style, init

from loguru import logger
from datetime import datetime
from urllib.parse import urlencode

init(autoreset=True)

BLACKDUCK_URL = "https://eu.polaris.blackduck.com/api"

# debug function, pretty print with indentation
def pp(json_data):
    if isinstance(json_data, str):
        json_data = json.loads(json_data)

    pretty_json = json.dumps(json_data, indent=4, sort_keys=True)
    print(pretty_json)

# displays the error message in the format required by github actions
def __panic__(message: str):
    print(f"::error::{message}")
    exit(1)

class BlackDuck:
    def __init__(self, token: str, sca_id: str, sast_id: str) -> None:
        logger.info("Starting BlackDuck Reporter")
        logger.info(f'Source SCA scan ID: "{sca_id}"')
        logger.info(f'Source SAST scan ID: "{sast_id}"')

        self.token = token
        self.get_test_info(sca_id, sast_id)
        self.get_branch_info(self.sca["projectId"])

    # terminate the program with the panic function if the status code falls outside the 200-399 range
    def get(self, endpoint: str, headers={}):
        headers["Api-Token"] = self.token
        try:
            response = requests.get(f"{BLACKDUCK_URL}{endpoint}", headers=headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as error:
            __panic__(error)

    def get_test_info(self, sca_id: str, sast_id: str):
        self.sca = self.get(f"/tests/{sca_id}")
        self.sast = self.get(f"/tests/{sast_id}")

    # TODO: this endpoint is deprecated in favor of /portfolios/{projectId}/branches, but it doesn't work properly yet
    def get_branch_info(self, project_id: str):
        branches = self.get(f"/portfolio/portfolio-sub-items/{project_id}/branches")
        branchMap = {item["id"]: item["name"] for item in branches["_items"]}

        self.sca["branchName"] = branchMap[self.sca["branchId"]]
        self.sast["branchName"] = branchMap[self.sast["branchId"]]
        
    def get_scan_issues(self, scan: any):
        scan["issues"] = []

        params = {
            "testId": scan["id"],
            "projectId": scan["projectId"],
            "_first": 100,  # max allowed pagination
            "_includeType": "true",
            "_includeContext": "true",
            "_includeFirstDetectedOn": "true",
            "_includeTriageProperties": "true",
            "_includeOccurrenceProperties": "true",
        }

        url = f"/findings/issues?{urlencode(params)}"

        while True:
            response = self.get(url)
            scan["issues"].extend(response["_items"])
            link = next((link for link in response["_links"] if link["rel"] == "next"), None)

            if not link:
                break

            # remove the base url from the url link
            url = link["href"].replace(BLACKDUCK_URL, "")
        
        logger.info(f'[{scan["assessmentType"]}] Found a total of {len(scan["issues"])} vulnerabilities in branch "{scan["branchName"]}"')


def build_description(issue: any) -> str:
    pp(issue)
    return ""
    # format the first detected date
    first_detected = datetime.strptime(issue.get("firstDetectedOn", ""), "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%b %d, %Y, %I:%M %p")

    # extract issue details
    issue_type = issue.get("type", {}).get("_localized", {})
    issue_name = issue_type.get("name", "Unknown")
    other_details = {d["key"]: d["value"] for d in issue_type.get("otherDetail", [])}
    
    # extract issue properties
    issue_properties = {p["key"]: p["value"] for p in issue.get("occurrenceProperties", [])}
    severity = issue_properties.get("severity", "Unknown").capitalize()
    cwe = issue_properties.get("cwe", "Unknown")
    spec_desc = issue_properties.get("description", "Unknown")
    location = issue_properties.get("location", "Unknown")
    line_number = issue_properties.get("line-number", "Unknown")
    component_name = issue_properties.get("component-name", "Unknown Component")
    component_version = issue_properties.get("component-version-name", "Unknown Version")
    vulnerability_id = issue_properties.get("vulnerability-id", "Unknown Vulnerability ID")
    technical_description = issue_properties.get("technical-description", "No technical description available.")
    solution = issue_properties.get("solution", "No solution available.")
    workaround = issue_properties.get("workaround", "No workaround available.")
    linked_vulnerability_id = issue_properties.get("linked-vulnerability-id", "No linked vulnerability.")
    vendor_fix_date = issue_properties.get("vendor-fix-date", "No vendor fix date available.")
    disclosure_date = issue_properties.get("disclosure-date", "No disclosure date available.")

    # build the description
    description = (
        f"*First Detected:*\n{first_detected}\n\n"
        f"*Issue Type:*\n{issue_name}\n\n"
        f"*Description:*\n{other_details.get('description', 'No description available.')}\n\n"
        f"*Specific Description:*\n{spec_desc}\n\n"
        f"*Local Effect:*\n{issue_properties.get('local-effect', 'No local effect available.')}\n\n"
        f"*Related To:*\n{cwe}\n\n"
        f"*Severity:*\n{severity}\n\n"
        f"*File Name:*\n{location}\n\n"
        f"*Line Number:*\n{line_number}\n\n"
        f"*Component:*\n{component_name} {component_version}\n\n"
        f"*Vulnerability ID:*\n{vulnerability_id}\n\n"
        f"*Technical Description:*\n{technical_description}\n\n"
        f"*Remediation:*\n{other_details.get('remediation', 'No remediation available.')}\n\n"
        f"*Workaround:*\n{workaround}\n\n"
        f"*Solution:*\n{solution}\n\n"
        f"*Linked Vulnerability ID:*\n{linked_vulnerability_id}\n\n"
        f"*Vendor Fix Date:*\n{vendor_fix_date}\n\n"
        f"*Disclosure Date:*\n{disclosure_date}\n\n"
    )

    return description

def print_sast_issues(issues: any):
    for issue in issues:
        first_detected = datetime.strptime(issue.get("firstDetectedOn", ""), "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%b %d, %Y, %I:%M %p")
        issue_name = issue['type']['_localized']['name'] if issue['type'].get('_localized') else "Unknown Issue Name"

        print(Fore.CYAN + Style.BRIGHT + f"━━━━━━━━━━━━━━━━━━ {issue_name} [Detected On: {Fore.YELLOW + first_detected + Fore.CYAN + Style.BRIGHT }] ━━━━━━━━━━━━━━━━━━\n")

        if issue['type'].get('_localized'):
            for detail in issue['type']['_localized']['otherDetails']:
                print(Fore.WHITE + f"{detail['key'].upper()}: {Fore.CYAN + detail['value']}")

        for prop in issue['occurrenceProperties']:
            print(Fore.WHITE + f"{prop['key'].upper()}: {Fore.CYAN + str(prop['value'])}")

        print("\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Polaris Scan Reporter")

    parser.add_argument("--token", help="BlackDuck API Token", required=True)
    parser.add_argument("--sca", help="BlackDuck SCA Scan ID", required=True)
    parser.add_argument("--sast", help="BlackDuck SAST Scan ID", required=True)

    args = parser.parse_args()
    
    blackduck = BlackDuck(args.token, args.sca, args.sast)
    blackduck.get_scan_issues(blackduck.sca)
    blackduck.get_scan_issues(blackduck.sast)
    
    print_sast_issues(blackduck.sast["issues"])
