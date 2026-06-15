from main import check_virustotal, check_abuseipdb, check_ipvoid

def test_ips():
    # สุ่ม IP สาธารณะมาทดสอบ 3 IP
    # 1. 8.8.8.8 (Google Public DNS - น่าจะ Clean)
    # 2. 1.1.1.1 (Cloudflare DNS - น่าจะ Clean)
    # 3. 185.153.199.117 (IP ที่มักจะมีการสแกน/โจมตี - อาจจะมีความเสี่ยง)
    test_ips_list = [
        "8.8.8.8",
        "1.1.1.1",
        "209.74.65.20"
    ]
    
    print("--- เริ่มการทดสอบตรวจสอบ IP (ไม่ผ่าน Jira) ---")
    for ip in test_ips_list:
        print(f"\n[*] กำลังตรวจสอบ IP: {ip}")
        
        # เรียกใช้ฟังก์ชันจาก main.py โดยตรง
        vt_result = check_virustotal(ip)
        ab_result = check_abuseipdb(ip)
        ipv_result = check_ipvoid(ip)
        
        print(f"  > {vt_result}")
        print(f"  > {ab_result}")
        print(f"  > {ipv_result}")
        
    print("\n--- สิ้นสุดการทดสอบ ---")

if __name__ == "__main__":
    test_ips()
