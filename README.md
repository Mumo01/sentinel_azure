# Azure Sentinel SIEM Portfolio Project

This project demonstrates using Azure Sentinel to analyze and visualize failed login attempts by gathering event logs, extracting geo-data, and plotting attacks on a map.

# Project Description

A cybersecurity-focused project using Azure Sentinel to analyze failed login attempts on a simulated vulnerable VM. The project involves collecting event logs, mapping IP geolocations via app.ipgeolocation.io, and visualizing attacks on an interactive map. This showcases expertise in SIEM configuration, data analysis, and threat visualization. 

<br>-<img src= "https://github.com/user-attachments/assets/c9dfa476-f04a-4ca9-ab44-ffa3c86098b8" height="80%" width="80%" alt=""/><br>

## **Devices Used**
- **Operating System:** MacOS  
- **Virtual Environment:** Azure Virtual Machine (Windows)

---

## **Project Steps**

### **1. Create VM on Azure and Allow All Traffic**
- **Purpose:** Simulate an exposed system to gather data on failed login attempts.
- **Steps:**
  1. Log into the [Azure Portal](https://portal.azure.com).
  2. Navigate to **Virtual Machines** and create a new VM.
  3. Choose a Windows OS (e.g., Windows Server 2019).
  4. Under **Create new security group**, set **Inbound Rules** to allow all traffic.
 <br>-<img src= "https://github.com/user-attachments/assets/737b0ee9-6176-4fb9-927c-90ffb56a51b8" height="80%" width="80%" alt=""/><br>

  5. Deploy the VM and note its public IP address.

---

### **2. Create Log Analytics Workspace**
- **Purpose:** Collect, analyze, and visualize data in Azure Sentinel.
- **Steps:**
  1. Navigate to **Log Analytics Workspaces** in the Azure Portal.
  2. Create a new workspace.
  3. Save the workspace details for linking to Azure Sentinel later.
  - <br>-<img src= "https://github.com/user-attachments/assets/6d55bd12-ee96-44e2-8b25-355c60875d95" height="80%" width="80%" alt=""/><br>
---

### **3. Disable Windows Firewall on the VM**
- **Purpose:** Intentionally increase vulnerability to allow unrestricted access for testing purposes.
- **Steps:**
  1. RDP into the VM.
  2. Open **Windows Defender Firewall** settings.
  3. Disable the firewall for all profiles (Domain, Private, and Public).
  4. Try to ping the virtual machine without any authorization
  <br>-<img src= "https://github.com/user-attachments/assets/220e7e09-b71b-4f86-bf5e-d05123befd16" height="80%" width="80%" alt=""/><br>

---

### **4. Download PowerShell Script**
- **Purpose:** Automate the retrieval of IP addresses from event logs.
- **Steps:**
  1. Write or download a PowerShell script to:
      - Query Windows Event Viewer for failed login attempts (Event ID 4625).
      - Extract IP addresses of failed logins.
  2. Save the script on the VM.

---

### **5. Obtain API Key from app.ipgeolocation.io**
- **Purpose:** Use the API to map IP addresses to geographic locations.
- **Steps:**
  1. To obtain an API key, Register at [app.ipgeolocation.io](https://app.ipgeolocation.io).
   - <br>-<img src= "https://github.com/user-attachments/assets/8b4b6495-f7d5-41cd-8ab5-6351b98f87e0" height="80%" width="80%" alt=""/><br>
  2. Add the API key to the PowerShell script for geolocation lookups.

---

### **6. Run the PowerShell Script and Check file created**
- **Purpose:** Collect failed login IP addresses, get their geo-data, and create a log file.
- **Steps:**
  1. Execute the PowerShell script on the VM.
  <br>-<img src= "https://github.com/user-attachments/assets/3ab3be1a-937c-4e30-a502-f3b89b079509" height="80%" width="80%" alt=""/><br>
  2. Confirm that the script generates log files in `C:\ProgramData\...`.
  3. Verify the log data contains metrics like longitude, latitude, country, etc.
  <br>-<img src= "https://github.com/user-attachments/assets/7f945082-089e-4539-8a5d-9d266de4352d" height="80%" width="80%" alt=""/><br>
  4. File created and stored in the C:\ProgramData\..
  <br>-<img src= "https://github.com/user-attachments/assets/38a39876-3303-449f-a6e0-64e12dc50692" height="80%" width="80%" alt=""/><br>
      
---

### **7. Transform Data**
- **Purpose:** Clean and structure data for visualization in Sentinel.
- **Steps:**
  1. Use PowerShell or Azure Log Analytics queries to:
      - Group failed login attempts by geo-metrics (longitude, latitude, country, etc.).
  <br>-<img src= "https://github.com/user-attachments/assets/368cba7a-dfe6-4fb2-9114-4ed2bc9ef08e" height="80%" width="80%" alt=""/><br>
  2. Save the transformed data for mapping.

---

### **8. Setup Map in Azure Sentinel**
- **Purpose:** Visualize attacks geographically.
- **Steps:**
  1. Link the Log Analytics Workspace to Azure Sentinel.
  2. Configure a Workbook in Sentinel to plot data on a map.
  3. Use longitude and latitude values from the logs.
- <br>-<img src= "https://github.com/user-attachments/assets/067eb769-ac46-4860-889d-8408c3ad4af8" height="80%" width="80%" alt=""/><br>
---

### **9. Visualize Results**
- **Purpose:** Gain insights into attack patterns.
- **Steps:**
  1. Open the map visualization in Azure Sentinel.
     <br>-<img src= "https://github.com/user-attachments/assets/1f49159d-2a5d-4128-9713-9e62d2675e34" height="80%" width="80%" alt=""/><br>
  3. Analyze the distribution of attacks. Go a step forward and even lookUp the IP of the attackers through any IP look-up sites.
     <br>-<img src= "https://github.com/user-attachments/assets/8f001859-7440-4e36-9934-2280dd0d870b" height="80%" width="80%" alt=""/><br>
     <br>-<img src= "https://github.com/user-attachments/assets/8f9ad04b-baef-498d-9013-1caf9d7a3320" height="80%" width="80%" alt=""/><br>

  4. Identify trends and high-risk regions.

---
# **Insights from Geo-Specific Attack Visualization**

### **1. Geographical Distribution of Attacks**
- **Brazil** has the highest number of failed RDP login attempts (105), suggesting it could be a hotspot for brute-force or automated attack bots.
- Other contributors include **Ukraine** (31 and 12 attempts from two IPs) and **Russia** (2 attempts), highlighting specific activity from Eastern Europe.

### **2. Attack Trends**
- A significant concentration of attempts in Brazil suggests potential botnet activity or a coordinated effort.
- Multiple IPs from Ukraine indicate distributed attack efforts rather than a single source.

### **3. Potential Threat Actors**
- The attackers may be leveraging compromised machines or proxy servers in different regions, making the real origin difficult to trace.

### **4. Security Vulnerability**
- The high volume of failed login attempts highlights that the RDP service is exposed and actively targeted, emphasizing the need for security measures.

### **5. Risk Prioritization**
- Focusing on blocking or restricting access from high-attack regions (e.g., Brazil) could significantly reduce the attack surface.

---

# **Mitigation Strategies**

### **1. Implement Geo-Blocking**
- **Description:** Restrict access from countries with high attack volumes, such as Brazil and Ukraine.
- **Action:** 
  - Configure Azure Network Security Groups (NSGs) or firewalls to block inbound RDP traffic from these regions.
  - Allow connections only from trusted IP ranges or specific countries.

### **2. Enforce Multi-Factor Authentication (MFA)**
- **Description:** Add an extra layer of security to RDP logins.
- **Action:**
  - Enable Azure AD MFA for accounts accessing the VM.
  - Use conditional access policies to enforce MFA for external login attempts.

### **3. Reduce Attack Surface**
- **Description:** Limit RDP access to only essential users.
- **Action:**
  - Disable public RDP access and allow only specific IPs.
  - Use Azure Bastion for secure, browser-based RDP access without exposing RDP ports.

### **4. Enable Intrusion Detection and Prevention**
- **Description:** Detect and block automated or brute-force login attempts in real-time.
- **Action:**
  - Use Azure Security Center and Sentinel to monitor suspicious login attempts.
  - Set up automated playbooks in Sentinel to block offending IPs immediately.

### **5. Strengthen Authentication**
- **Description:** Minimize reliance on passwords for access.
- **Action:**
  - Disable password-based authentication and use certificates or Azure AD credentials.
  - Require complex passwords and implement regular password rotation.

### **6. Set Up Account Lockout Policies**
- **Description:** Prevent brute-force attempts by locking accounts after repeated failed logins.
- **Action:**
  - Configure local group policy on the VM to lock accounts after a set number of failed login attempts.

### **7. Monitor and Analyze Logs**
- **Description:** Continuously review logs for unusual patterns or spikes in login failures.
- **Action:**
  - Use Azure Log Analytics to track failed login attempts over time.
  - Set up alerts in Sentinel for suspicious activity (e.g., multiple failures from a single IP).

### **8. Patch and Secure the System**
- **Description:** Mitigate vulnerabilities that attackers might exploit.
- **Action:**
  - Regularly apply Windows updates and patches to the VM.
  - Disable unused services and ports to minimize attack vectors.

### **9. Leverage Threat Intelligence**
- **Description:** Block known malicious IPs using threat intelligence feeds.
- **Action:**
  - Enable Azure Sentinel's threat intelligence integration to proactively block known bad actors.

### **10. Use Network Access Control (NAC)**
- **Description:** Ensure only authorized devices can access the VM.
- **Action:**
  - Configure NAC policies to verify devices before granting access.
  - Use Azure Conditional Access to restrict connections based on device compliance and health.

---

## **Deliverables**
1. **Screenshots/Walkthrough:**
   - VM setup, firewall settings, script execution, Sentinel configuration, and final map visualization.
2. **Insights:**
   - Observations on attack patterns and trends.
3. **Reflection:**
   - Mitigation strategies (e.g., IP blocking, implementing MFA).
  
     
---

## **Additional Notes**
- Ensure the VM is terminated after the project to avoid unnecessary costs.
  <br>-<img src= "https://github.com/user-attachments/assets/a4cf4bf4-a7af-42d2-a88e-afe7b5c809b8" height="80%" width="80%" alt=""/><br>
  
# This setup intentionally disables security to simulate attacks, **DO NOT TRY THIS** in production environments.

