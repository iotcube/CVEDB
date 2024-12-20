import json
import re
import os
import jellyfish
from urllib.parse import urlparse

#version mappling -> 먼저 repo랑 cpe Dict 만들고 진행해야할 듯

ROOT_DIR = ''
NVD_CVE_JSON_PATH = ROOT_DIR + '241205_NVD_CVE_JSON'
NVD_MATCH_JSON_PATH = ROOT_DIR + 'nvdcpematch-1.0.json'
RESULT_JSON_PATH = ROOT_DIR + "result_241216.json"

abbreviation_keywords = ['poc', 'rce', 'dos', 'csrf', 'xss', 'vul', 'crash', 'cve', 'sqli', 'vuln', 'vuls','ctf','cve','0day']
full_keywords = ['vulnerability', 'bigtiger', 'exploit', 'bugreport', 'attack',
                 'injection', 'vulnerabilities', 'bufferoverflow', 'crosssitescripting',
                 'remotecodeexecution', 'executecode', 'fileupload', 'overflow', 'invalidfree',
                 'commandexecution', 'shellupload', 'codereuse', 'nullpointer', 'blockchainssecurity',
                 'security-advisories', 'security-bulletins', 'security_monkey','advisories','execution','issues','security-advisories',
                 'security-bulletins','security-monkey','bugbounty']
cpe_match_data = None
cve_json_data = None

def log_failure(cve_id, cpe): 
    with open(ROOT_DIR + "failed_log_241212.txt", "a", encoding="utf-8") as log_file:
        log_file.write(f"CVE-ID: {cve_id}, CPE: {cpe}\n")

def load_cpe_match_data():
    global cpe_match_data
    if cpe_match_data is None:
        with open(NVD_MATCH_JSON_PATH, 'r', encoding='utf-8') as f:
            cpe_match_data = json.load(f)
        print('cpe match done')
    return cpe_match_data

def load_json_data():
    global cve_json_data
    if cve_json_data is None:
        with open(RESULT_JSON_PATH, 'r', encoding='utf-8') as f:
            cve_json_data = json.load(f)
        print('result json done')
    return cve_json_data

def contains_abbreviation_keyword(url):
    url_lower = url.lower()
    for keyword in abbreviation_keywords:
        if re.search(rf'\b{re.escape(keyword)}\b', url_lower):
            return True
    return False

def contains_full_keyword(url):
    url_lower = url.lower()
    for keyword in full_keywords:
        if keyword in url_lower:
            return True
    return False

def extract_all_version(match):
    version_list = []
    for cpe in match.get('cpe_name', []):
        versions = cpe['cpe23Uri'].split(':')
        if versions[5] not in ('*','-'):
            if versions[6] not in ('*','-'):
                version_list.append(f'{versions[5]}-{versions[6]}')
            version_list.append(versions[5])
    return version_list


def nvd_cve_match(cpe,cpe_match_data):
    vendor, product, version, vs_incl, vs_excl, ve_incl, ve_excl = cpe
    version_list = []

    for match in cpe_match_data.get('matches',[]):
        match_cpe = match.get('cpe23Uri')
        if not match_cpe:
            continue

        parts = match_cpe.split(':')
        v, p = parts[3], parts[4]

        if vendor != v or product != p:
            continue

        has_version_range = any([
            match.get('versionStartIncluding'),
            match.get('versionStartExcluding'),
            match.get('versionEndIncluding'),
            match.get('versionEndExcluding')
        ])

        if has_version_range:
            for cpe_names in match.get('cpe_name',[]):
                cpe23Uri = cpe_names.get('cpe23Uri')
                cpe23Uri_parts = cpe23Uri.split(':')
                if len(cpe23Uri_parts)>5:
                    cpe23Uri_version = cpe23Uri_parts[5]
                    cpe23Uri_update = cpe23Uri_parts[6]
                    if cpe23Uri_version not in ('*','-'):
                        if cpe23Uri_update not in ('*','-'):
                            version_list.append(f'{cpe23Uri_version}-{cpe23Uri_update}')
                        else:
                            version_list.append(cpe23Uri_version)
    version_list = sorted(list(set(version_list)))
    return version_list
    '''vendor, product, version, vs_incl, vs_excl, ve_incl, ve_excl = cpe
    version_list = []
    for match in cpe_match_data.get('matches', []):
        if match['cpe23Uri'] == cpe :
            if match['cpe_name']:
                if vs_incl and match.get('versionStartIncluding') == vs_incl:
                    version_list.extend(extract_all_version(match))
                if vs_excl and match.get('versionStartExcluding') == vs_excl:
                    version_list.extend(extract_all_version(match))
                if ve_incl and match.get('versionEndIncluding') == ve_incl:
                    version_list.extend(extract_all_version(match))
                if ve_excl and match.get('versionEndExcluding') == ve_excl:
                    version_list.extend(extract_all_version(match))
    return list(set(version_list))'''

def extract_url(references):
    urls = set()
    for ref in references:
        url = ref.get('url', '')
        if url and not contains_abbreviation_keyword(url) and not contains_full_keyword(url):
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            if 'github.com' in domain:
                urls.add(url)
    return urls

def extract_cpe(cpe_data):
    cpe_result = set()
    for cpe in cpe_data.get('cpe_match', []):
        if 'cpe23Uri' in cpe:
            cpe_parts = cpe['cpe23Uri'].split(':')
            if len(cpe_parts) < 6:
                continue
            vendor = cpe_parts[3]
            product = cpe_parts[4]
            version = cpe_parts[5] if len(cpe_parts) > 5 else ''
            update = cpe_parts[6] if len(cpe_parts) > 6 else ''
            if update and update not in ('*','-'):
                version = f'{version}-{update}'

            versionStartIncluding = cpe.get('versionStartIncluding')
            versionStartExcluding = cpe.get('versionStartExcluding')
            versionEndIncluding = cpe.get('versionEndIncluding')
            versionEndExcluding = cpe.get('versionEndExcluding')
            cpe_result.add((vendor, product, version, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding))
    return cpe_result

def update_data_key(cpe, key, cve_id, version_list, version_range_list):
    vendor, product, version, vs_incl, vs_excl, ve_incl, ve_excl = cpe
    repo_data = cve_json_data[key]

    cpe_str = f'{vendor}:{product}'
    if cpe_str not in repo_data['cpe']:
        repo_data['cpe'].append(cpe_str)

    if "versions" not in repo_data:
        repo_data["versions"] = {}
    for ver in version_list:
        if ver not in repo_data['versions']:
            repo_data['versions'][ver] = []
        if cve_id not in repo_data['versions'][ver]:
            repo_data['versions'][ver].append(cve_id)

    if "version_ranges" not in repo_data or isinstance(repo_data['version_ranges'], dict):
        repo_data['version_ranges'] = []

    for vr in version_range_list:
        found = False
        for existing_vr in repo_data['version_ranges']:
            if all(vr.get(k) == existing_vr.get(k) for k in ["versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"]):
                for cid in vr.get('cve_ids', []):
                    if cid not in existing_vr['cve_ids']:
                        existing_vr['cve_ids'].append(cid)
                found = True
                break
        if not found:
            repo_data['version_ranges'].append(vr)

    cve_json_data[key] = repo_data


def update_json_db(cpe, cve_id, url, version_list, version_range_list):
    vendor, product, version, vs_incl, vs_excl, ve_incl, ve_excl = cpe

    if url:
        match = re.match(r'https?://github\.com/([^/]+)/([^/]+)', url)
        if match: 
            owner, repo = match.groups()
        else:
            log_failure(cve_id, cpe)
            return
    else:
        log_failure(cve_id, cpe)
        return

    if product in cve_json_data:
        update_data_key(cpe, product, cve_id, version_list, version_range_list)
    elif repo in cve_json_data:
        update_data_key(cpe, repo, cve_id, version_list, version_range_list)
    elif repo == product:
        cve_json_data[repo] = {
            "repo": f"{owner}/{repo}",
            "cpe": [],
            "versions": {},
            "version_ranges": []
        }
        update_data_key(cpe, repo, cve_id, version_list, version_range_list)
    else:
        log_failure(cve_id, cpe)

def find_similliar_key(product):
    best_key = None
    best_score = 0.0
    for key in cve_json_data.keys():
        score = jellyfish.jaro_winkler_similarity(key, product)
        if score > best_score:
            best_score = score
            best_key = key
    return best_score, best_key

def create_db():
    load_cpe_match_data() #nvdcpematch JSON 파일 로드 (version range에서 version 추출 위함)
    load_json_data()      #NVD CVE JSON 파일 로드

    for year in range(2002, 2024 + 1):
        file_path = os.path.join(NVD_CVE_JSON_PATH, f'nvdcve-1.1-{year}.json')
        if not os.path.exists(file_path):
            continue

        with open(file_path, 'r', encoding='utf-8') as file:
            print(file)
            data = json.load(file)

            for item in data['CVE_Items']:
                cve_id = item['cve']['CVE_data_meta']['ID'] 
                configurations = item.get('configurations', {}).get('nodes', []) 
                references = item.get('cve', {}).get('references', {}).get('reference_data', [])  
                reference_urls = extract_url(references)
                cpe_datas = set()

                for node in configurations:
                    cpe_datas.update(extract_cpe(node))
                    for child in node.get('children', []):
                        cpe_datas.update(extract_cpe(child))

                # URL 없는 경우 처리
                if not reference_urls: 
                    cpe_list = [cpe for cpe in cpe_datas]
                    for cpe in cpe_list :
                        vendor, product, version, vs_incl, vs_excl, ve_incl, ve_excl = cpe
                        score, key = find_similliar_key(product)
                        version_list = []
                        version_range_list = []
                        if score > 0.85:
                            if version not in ('*','-'):
                                version_list.append(version)
                            vr_dict = {}
                            if vs_incl or vs_excl or ve_incl or ve_excl:
                                version_ranges = nvd_cve_match(cpe,cpe_match_data)
                                if version_ranges:
                                    version_list.extend(version_ranges)
                                else:
                                    vr_dict = {}
                                    if vs_incl:
                                        vr_dict["versionStartIncluding"] = vs_incl
                                    if vs_excl:
                                        vr_dict["versionStartExcluding"] = vs_excl
                                    if ve_incl:
                                        vr_dict["versionEndIncluding"] = ve_incl
                                    if ve_excl:
                                        vr_dict["versionEndExcluding"] = ve_excl
                                    vr_dict["cve_ids"] = [cve_id]
                                    if vr_dict:
                                        version_range_list.append(vr_dict)
                            version_list = sorted(list(set(version_list)))
                            update_data_key(cpe, key, cve_id, version_list, version_range_list)

                else:
                    for url in reference_urls:
                        cpe_list = [cpe for cpe in cpe_datas]
                        for cpe in cpe_list:
                            vendor, product, version, vs_incl, vs_excl, ve_incl, ve_excl = cpe
                            version_list = []
                            version_range_list = []

                            if version not in ('*','-'):
                                version_list.append(version)
                            if vs_incl or vs_excl or ve_incl or ve_excl:
                                version_ranges = nvd_cve_match(cpe,cpe_match_data)
                                if version_ranges:
                                    version_list.extend(version_ranges)
                                else:
                                    vr_dict = {}
                                    if vs_incl:
                                        vr_dict["versionStartIncluding"] = vs_incl
                                    if vs_excl:
                                        vr_dict["versionStartExcluding"] = vs_excl
                                    if ve_incl:
                                        vr_dict["versionEndIncluding"] = ve_incl
                                    if ve_excl:
                                        vr_dict["versionEndExcluding"] = ve_excl
                                    vr_dict["cve_ids"] = [cve_id]
                                    if vr_dict:
                                        version_range_list.append(vr_dict)
                            version_list = sorted(list(set(version_list)))
                            update_json_db(cpe,cve_id,url,version_list,version_range_list)

    with open(RESULT_JSON_PATH, 'w', encoding='utf-8') as f:
        json.dump(cve_json_data, f, ensure_ascii=False, indent=4)

def main():    
    create_db()

if __name__ == "__main__":
    main()
