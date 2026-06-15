from fastapi import FastAPI, Request
import re
import requests
import json
import pycountry
from jira import JIRA
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI()

# ==========================================
# 1. ตั้งค่า Config และ API Keys
# ==========================================
JIRA_URL = "https://automedthridparty.atlassian.net" 
JIRA_EMAIL = "puttimet.butngoen@gmail.com"
JIRA_TOKEN = "ATATT3xFfGF0NE03-GY7StW55c-IzqRZHPe1MUN76_DTuwT1LitRe9_SmAKNG-f5g07KRJ8PwYuajFf4wU9tiHINs-cnLBpeJ-AN5GrEu51HAPF7uVT89Ipftis1CUjsb7jnwdpW_LwJ8TLqPvZf9kPz5Zy3feTKRK3qwNZ6Xanm3zfmIQBXujQ=B5B09DAD"

VT_API_KEY = "b790aeecec01f7e37fb95449ddfe115e260de8bf362e808c97012e5f53b48922"
AB_API_KEY = "f12f7397e6eddb6dd64053c3306b529cb66c2cde5e04f3039bcb20aeb80a1108ac5f908efcf0cd57"
ALIENVAULT_API_KEY = "e7bbf69e488969fa885ff9f113e060710ebbbb765d6323f6b6aaa78f53c8524c" 

try:
    jira = JIRA(server=JIRA_URL, basic_auth=(JIRA_EMAIL, JIRA_TOKEN))
    print(f"\n[OK] บอทเชื่อมต่อกับ Jira สำเร็จ: {JIRA_URL}")
except Exception as e:
    print(f"\n[ERROR] เชื่อมต่อ Jira ไม่สำเร็จ: {e}")

# ==========================================
# 2. ฟังก์ชันช่วยเหลือ (Helper Functions)
# ==========================================
def get_country_display(country_code):
    """แปลงตัวย่อประเทศ เป็นชื่อเต็มพร้อมธงชาติ"""
    if not country_code or country_code == 'N/A':
        return "🏳️ Unknown"
    
    code = country_code.upper()
    
    # 1. แปลงรหัสเป็นชื่อประเทศเต็ม
    try:
        country_obj = pycountry.countries.get(alpha_2=code)
        full_name = country_obj.name if country_obj else code
    except:
        full_name = code
        
    # 2. ทริคแปลงรหัส 2 ตัวอักษรเป็น Emoji ธงชาติ (Unicode Offset)
    try:
        flag = chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
    except:
        flag = "🏳️"
        
    return f"{flag} {full_name}"

# ==========================================
# 3. ฟังก์ชันตรวจสอบ Threat Intel
# ==========================================
def check_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            attrs = response.json()['data']['attributes']
            stats = attrs.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            
            # สกัดข้อมูลที่สำคัญสำหรับ SOC
            owner = attrs.get('as_owner', 'N/A')
            asn = attrs.get('asn', 'N/A')
            network = attrs.get('network', 'N/A')
            reputation = attrs.get('reputation', 0)
            country_display = get_country_display(attrs.get('country', 'N/A'))
            
            header = f"🔴 *VirusTotal:* ภัยคุกคาม {malicious} engines" if malicious > 0 else "🟢 *VirusTotal:* Clean"
            details = (
                f"\n      ├ Owner: {owner} (ASN: {asn})"
                f"\n      ├ Network: {network}"
                f"\n      ├ Reputation Score: {reputation}"
                f"\n      └ Country: {country_display}"
            )
            return header + details
    except: pass
    return "⚪ *VirusTotal:* Error/No Data"

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {'Accept': 'application/json', 'Key': AB_API_KEY}
    try:
        response = requests.get(url, headers=headers, params={'ipAddress': ip, 'maxAgeInDays': '90'})
        if response.status_code == 200:
            data = response.json()['data']
            score = data.get('abuseConfidenceScore', 0)
            reports = data.get('totalReports', 0)
            
            # สกัดข้อมูลที่สำคัญสำหรับ SOC
            isp = data.get('isp', 'N/A')
            usage = data.get('usageType', 'N/A')
            domain = data.get('domain', 'N/A')
            is_white = "✅ Yes" if data.get('isWhitelisted') else "❌ No"
            last_rep = data.get('lastReportedAt', 'N/A')[:10] # ตัดเอาแค่วันที่ YYYY-MM-DD
            country_display = get_country_display(data.get('countryCode', 'N/A'))
            
            header = f"🔴 *AbuseIPDB:* เสี่ยง {score}% ({reports} รีพอร์ต)" if score > 0 else "🟢 *AbuseIPDB:* Clean"
            details = (
                f"\n      ├ ISP: {isp}"
                f"\n      ├ Usage Type: {usage}"
                f"\n      ├ Domain: {domain}"
                f"\n      ├ Last Reported: {last_rep}"
                f"\n      └ Country: {country_display}"
            )
            return header + details
    except: pass
    return "⚪ *AbuseIPDB:* Error/No Data"

def check_alienvault(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            
            # 1. จัดการข้อมูล Pulse (แคมเปญการโจมตี)
            pulse_info = data.get('pulse_info', {})
            pulses_count = pulse_info.get('count', 0)
            
            # ดึงชื่อแคมเปญล่าสุดออกมา (ถ้ามีประวัติ) มีประโยชน์มากเวลา Triage
            latest_pulse_name = "N/A"
            if pulses_count > 0 and 'pulses' in pulse_info and len(pulse_info['pulses']) > 0:
                latest_pulse_name = pulse_info['pulses'][0].get('name', 'Unknown')
            
            # 2. สกัดข้อมูลแวดล้อมอื่นๆ สำหรับ SOC
            asn = data.get('asn', 'N/A')
            city = data.get('city', 'N/A') or "Unknown" # ดักจับกรณีเป็น None
            reputation = data.get('reputation', 0)
            
            country_code = data.get('country_code', 'N/A')
            country_display = get_country_display(country_code)
            
            # 3. จัด Format การแสดงผล
            header = f"🔴 *AlienVault OTX:* พบใน {pulses_count} แคมเปญ (Pulses)" if pulses_count > 0 else "🟢 *AlienVault OTX:* Clean"
            
            details = (
                f"\n      ├ Reputation Score: {reputation}"
                f"\n      ├ ASN: {asn}"
                f"\n      ├ City: {city}"
            )
            
            # โชว์ชื่อแคมเปญล่าสุดเฉพาะกรณีที่มันติด Blacklist (เพิ่มมิติให้ข้อมูล)
            if pulses_count > 0:
                details += f"\n      ├ Latest Campaign: {latest_pulse_name}"
                
            details += f"\n      └ Country: {country_display}"
            
            return header + details
        else:
            return f"⚪ *AlienVault OTX:* HTTP Error {response.status_code}"
    except Exception as e: 
        return f"⚪ *AlienVault OTX:* Code Error ({str(e)})"

# ==========================================
# 4. จุดรับ Webhook จาก Jira
# ==========================================
@app.post("/jira-webhook")
async def handle_jira_webhook(request: Request):
    raw_body = await request.body()
    data = json.loads(raw_body)
    
    issue_key = data.get('issue', {}).get('key') or data.get('key') or "Unknown"
    print(f"\n[*] ------------------------------------")
    print(f"[*] ได้รับ Ticket ใหม่: {issue_key}")

    all_data_str = json.dumps(data)
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    found_ips = list(set(re.findall(ip_pattern, all_data_str)))
    
    unique_public_ips = [ip for ip in found_ips if not ip.startswith(('10.', '192.168.', '127.', '172.'))]
    
    if not unique_public_ips:
        print(f"[-] ไม่พบ Public IP ใน Ticket {issue_key}")
        return {"status": "no public ip found"}

    print(f"[+] ตรวจพบ IP ที่ต้องตรวจสอบ: {unique_public_ips}")
    
    comment_body = "🤖 *Automated SOC Triage Report*\n\n"
    for ip in unique_public_ips:
        vt = check_virustotal(ip)
        ab = check_abuseipdb(ip)
        otx = check_alienvault(ip) 
        
        comment_body += f"* **IP:** `{ip}`\n"
        comment_body += f"   - {vt}\n"
        comment_body += f"   - {ab}\n"
        comment_body += f"   - {otx}\n\n"
        
        print(f"[+] ตรวจสอบ {ip} และดึงข้อมูลแวดล้อมเสร็จสิ้น")

    if issue_key != "Unknown":
        try:
            jira.add_comment(issue_key, comment_body)
            print(f"[SUCCESS] พ่นคอมเมนต์ลงใน {issue_key} เรียบร้อย!")
        except Exception as e:
            print(f"[FAILED] ส่งคอมเมนต์ไม่ได้: {e}")

    return {"status": "success"}