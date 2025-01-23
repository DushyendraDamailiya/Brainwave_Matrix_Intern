# Brainwave_Matrix_Intern
Phishing Link Scanner
# Phishing Link Scanner Project

## 1. What Is This Project?

This project is a **Phishing Link Scanner**, a software tool designed to analyze URLs and determine their safety. The scanner checks for suspicious patterns, verifies whether the URL is blacklisted, and provides users with detailed results. By identifying potential threats, this tool helps users avoid phishing attacks and maintain their cybersecurity.

Phishing is a common cyberattack where malicious websites mimic legitimate ones to steal sensitive information. This project addresses this issue by providing a simple, user-friendly application for detecting phishing attempts.

---

## 2. What Is the Work of This Software?

The primary objective of the **Phishing Link Scanner** is to evaluate a given URL and provide insights into its potential risks. Below are the key functionalities of the software:

### a. **URL Analysis**
The software performs a comprehensive scan of the input URL to identify:
- **Suspicious Patterns**: Matches common phishing indicators such as keywords (e.g., "login," "verify"), IP addresses in URLs, and excessive hyphens.
- **Blacklist Check**: Verifies if the URL is part of a predefined list of known malicious websites.
- **Shortened URL Expansion**: Automatically expands shortened URLs to reveal their full destination for better analysis.

### b. **Detailed Threat Report**
If the URL is found to be unsafe, the tool:
- Highlights the specific patterns detected in the URL that make it suspicious.
- Explains why these patterns are indicative of phishing threats.
- Alerts users if the URL is part of the blacklist.

### c. **Report Generation**
Users can save the scan results as a PDF document for record-keeping or sharing purposes. The results include:
- The analyzed URL.
- A summary of findings.
- Detailed explanations of any detected threats.

### d. **User-Friendly Interface**
The application is built with an intuitive **GUI** (Graphical User Interface) that allows even non-technical users to:
- Input URLs for scanning.
- View results in an organized format.
- Save reports with a single click.

---

## 3. How to Use This Software?

### Step 1: **Launch the Application**
Run the Python script to open the application. The main interface will appear with options to input a URL, scan it, and view results.

### Step 2: **Input the URL**
- Enter the URL you want to analyze in the text field provided.
- Ensure that the URL is correctly formatted.

### Step 3: **Scan the URL**
- Click the **"Scan URL"** button to initiate the scanning process.
- The application will:
  - Expand the URL if it is shortened.
  - Analyze the URL for suspicious patterns.
  - Check if the URL is blacklisted.

### Step 4: **View Results**
- The results of the scan will be displayed in the "Scan Results" section.
- If suspicious patterns are found, they will be highlighted with explanations.
- The blacklist status of the URL will also be shown.

### Step 5: **Save Results**
- To save the scan results, click the **"Save Results"** button.
- Choose a file location and name for the PDF report. The report will include all findings from the scan.

### Step 6: **Reset for a New Scan**
- Click the **"Reset"** button to clear the input field and results section.
- Input a new URL for scanning.
- 
## Screenshot
<img src ="https://github.com/user-attachments/assets/d5b586ba-ac85-4ac1-9f22-4b23bc1fb258" height="450" width="500">

## 4. Conclusion

The **Phishing Link Scanner** is an essential tool for anyone concerned about cybersecurity. It provides a reliable way to evaluate URLs, detect potential threats, and take preventive measures. By leveraging this tool, users can avoid phishing attacks and ensure safer browsing.

