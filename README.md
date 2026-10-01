# Automated SOC Triage Report Bot (Automate 3rd Party)

โครงงานนี้ถูกสร้างขึ้นเพื่อลดระยะเวลาและป้องกันความผิดพลาด (Human Error) จากกระบวนการทำงานแบบ Manual ของเจ้าหน้าที่ SOC[cite: 68, 69] โดยระบบจะทำการดึงข้อมูลภัยคุกคามจากหลายแหล่งพร้อมกันแบบอัตโนมัติ เพื่อสนับสนุนวิสัยทัศน์ขององค์กรที่ต้องการผลักดันให้การทำงานเป็น Automation[cite: 69]

## 🛠️ เครื่องมือที่ใช้ในการพัฒนา (Tech Stack)
* **Python & FastAPI:** ภาษาและ Framework หลักที่ใช้สร้าง Web Server (Endpoint) เพื่อรอรับข้อมูล Webhook ได้อย่างรวดเร็ว[cite: 71]
* **Jira API & Ngrok:** ใช้ Jira API ในการอ่านและเขียนผลลัพธ์กลับไปยังเคส และใช้ Ngrok สำหรับ Forward Port เครื่อง Local ออกสู่อินเทอร์เน็ต[cite: 71]
* **Threat Intel APIs:** เชื่อมต่อ API ภายนอก 3 แหล่ง ได้แก่ VirusTotal, AbuseIPDB และ AlienVault OTX[cite: 71]

## ⚙️ หลักการทำงานของระบบ (Workflow)
1. **รับ Webhook:** เมื่อมี Incident Case ใหม่ถูกสร้างขึ้น Jira จะส่งข้อมูล Ticket ทั้งหมดมาที่ Endpoint (FastAPI) อัตโนมัติ[cite: 72]
2. **สกัด Public IP:** ระบบใช้ Regex ค้นหา IP และกรอง Private IP ออก เพื่อตรวจสอบเฉพาะ IP ที่มีความเสี่ยงจริง[cite: 72]
3. **ตรวจสอบ 3rd Party:** เรียก API พร้อมกัน 3 แหล่ง (VirusTotal, AbuseIPDB, OTX) เพื่อดึงข้อมูลเชิงลึก เช่น Reputation Score, ISP, Campaign[cite: 72]
4. **อัปเดตผลลัพธ์:** รวบรวมผลลัพธ์จัดหน้าเป็น Automated Triage Report และเขียนกลับเป็น Comment ใน Jira Ticket ทันที[cite: 72]

## 🚀 ผลลัพธ์การทำงาน (Result)
ระบบสามารถรับข้อมูล วิเคราะห์ และแจ้งผลกลับเข้าไปใน Jira ได้สำเร็จภายในไม่กี่วินาที[cite: 74] โดยนักวิเคราะห์สามารถเห็นผลการวิเคราะห์ได้ทันทีใน Ticket ไม่ต้องสลับหน้าจอไปมา[cite: 76] ซึ่งรายงานผลประกอบด้วย:
* **VirusTotal:** จำนวน Engine ที่มองว่าเป็นภัยคุกคาม, AS Owner, Reputation Score[cite: 74]
* **AbuseIPDB:** เปอร์เซ็นต์ความเสี่ยง, จำนวนการโดน Report ใน 90 วัน, ข้อมูล ISP/Domain[cite: 74]
* **AlienVault OTX:** จำนวน Campaign (Pulses) ที่ IP นี้เข้าไปเกี่ยวข้อง[cite: 74]
