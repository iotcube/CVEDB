import requests
import time
import json
from datetime import datetime
import os

GITHUB_API_URL = "https://api.github.com/search/repositories"
GITHUB_TOKEN = ""

repositories = {}

headers = {
    "Authorization": f"token {GITHUB_TOKEN}"
}

ROOT_DIR = ''
RESULT_FILE = ROOT_DIR + 'result.json.'

if os.path.exists(RESULT_FILE) and os.path.getsize(RESULT_FILE) > 0:
    with open(RESULT_FILE, 'r', encoding='utf-8') as f:
        try:
            all_repositories = json.load(f)
        except json.JSONDecodeError:
            all_repositories = {}
else:
    all_repositories = {}

def get_repositories_for_period(start_date, end_date, lang):
    repos = {}
    query = f"stars:>500 language:{lang} created:{start_date}..{end_date}"
    per_page = 100
    max_pages = 10

    for page in range(1, max_pages + 1):
        params = {
            'q': query,
            'sort': 'stars',
            'order': 'desc',
            'per_page': per_page,
            'page': page
        }
        response = requests.get(GITHUB_API_URL, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            items = data.get("items", [])
            if not items:
                break
            for item in items:
                repo_key = item['name']
                if repo_key not in all_repositories and repo_key not in repos:
                    repos[repo_key] = {
                        "repo": f"{item['owner']['login']}/{item['name']}",
                        "cpe": [],
                        "versions": {},
                        "version_ranges": []
                    }
        else:
            print(f"Error: {response.status_code}")
            print(response.json())
            break
        time.sleep(2)
    return repos

languages = ["Python", "JavaScript", "Go", "Java", "C%2B%2B","C","Rust","C%23"]

start_year = 2008
end_year = datetime.now().year

for lang in languages:
    print(f"Collecting for language: {lang}")
    for year in range(start_year, end_year + 1):
        start_date = f"{year}-01-01"
        end_date = f"{year}-12-31"
        if year == end_year:
            end_date = datetime.now().strftime("%Y-%m-%d")

        print(f"  Collecting for {start_date}..{end_date}")
        yearly_repos = get_repositories_for_period(start_date, end_date, lang)
        for k, v in yearly_repos.items():
            if k not in all_repositories:
                all_repositories[k] = v
        time.sleep(5)

with open(RESULT_FILE, 'w', encoding='utf-8') as f:
    json.dump(all_repositories, f, ensure_ascii=False, indent=4)

print("Done")
