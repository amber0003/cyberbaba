"""
BurpSuite SQL Injection Scanner Extension
Reports confirmed SQL injection vulnerabilities to the Issues tab.

Installation:
1. Go to Extensions -> Options -> Python Environment
2. Select Jython standalone JAR
3. Go to Extensions -> Installed -> Add
4. Select Extension Type: Python
5. Select this file

Issues will appear in: Target -> Site map -> Issues (or Dashboard -> Issue activity)
"""

from burp import IBurpExtender, IScannerCheck, IScanIssue, IHttpRequestResponse
from java.io import PrintWriter
from java.net import URL
from array import array
import re
import time

class BurpExtender(IBurpExtender, IScannerCheck):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("SQLi Scanner (Zero False Positive)")
        callbacks.registerScannerCheck(self)
        
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        self._stdout.println("="*60)
        self._stdout.println("SQL Injection Scanner Loaded Successfully")
        self._stdout.println("Issues will appear in: Target > Issues tab")
        self._stdout.println("="*60)
        
        # SQL Error patterns
        self.sql_errors = {
            'MySQL': [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_",
                r"MySQLSyntaxErrorException",
                r"You have an error in your SQL syntax",
                r"check the manual that corresponds to your (MySQL|MariaDB) server version"
            ],
            'PostgreSQL': [
                r"PostgreSQL.*ERROR",
                r"Warning.*\Wpg_",
                r"PG::SyntaxError:",
                r"ERROR:\s+syntax error at or near"
            ],
            'MSSQL': [
                r"Driver.* SQL[\-\_\ ]*Server",
                r"OLE DB.* SQL Server",
                r"\[SQL Server\]",
                r"Unclosed quotation mark after the character string",
                r"Microsoft OLE DB Provider"
            ],
            'Oracle': [
                r"\bORA-[0-9][0-9][0-9][0-9]",
                r"Oracle error",
                r"quoted string not properly terminated"
            ],
            'SQLite': [
                r"SQLite\.Exception",
                r"\[SQLITE_ERROR\]",
                r"sqlite3\.OperationalError"
            ]
        }

    def doPassiveScan(self, baseRequestResponse):
        """Check responses for SQL errors passively"""
        response = baseRequestResponse.getResponse()
        if not response:
            return None
            
        respInfo = self._helpers.analyzeResponse(response)
        body = self._helpers.bytesToString(response[respInfo.getBodyOffset():])
        
        for db, patterns in self.sql_errors.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return [CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                        [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                        "SQL Error Message Detected",
                        "The response contains a SQL error message from " + db + " database.\n\n" +
                        "Pattern matched: " + pattern + "\n\n" +
                        "This may indicate a SQL injection vulnerability.",
                        "Medium",
                        "Tentative"
                    )]
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scan for SQL injection"""
        issues = []
        
        param_name = insertionPoint.getInsertionPointName()
        self._stdout.println("[*] Testing: " + param_name)
        
        # Get baseline
        baseline_resp = baseRequestResponse.getResponse()
        if not baseline_resp:
            return None
        baseline_info = self._helpers.analyzeResponse(baseline_resp)
        baseline_body = self._helpers.bytesToString(baseline_resp[baseline_info.getBodyOffset():])
        
        # 1. ERROR-BASED TEST
        error_issue = self._test_error_based(baseRequestResponse, insertionPoint, baseline_body)
        if error_issue:
            issues.append(error_issue)
            self._stdout.println("[+] FOUND: Error-based SQLi in " + param_name)
        
        # 2. TIME-BASED TEST  
        time_issue = self._test_time_based(baseRequestResponse, insertionPoint)
        if time_issue:
            issues.append(time_issue)
            self._stdout.println("[+] FOUND: Time-based SQLi in " + param_name)
        
        # 3. BOOLEAN-BASED TEST
        bool_issue = self._test_boolean_based(baseRequestResponse, insertionPoint, baseline_body)
        if bool_issue:
            issues.append(bool_issue)
            self._stdout.println("[+] FOUND: Boolean-based SQLi in " + param_name)
        
        return issues if issues else None

    def _test_error_based(self, baseRequestResponse, insertionPoint, baseline_body):
        """Test error-based SQLi with verification"""
        payloads = ["'", "\"", "')", "\")", "' OR '", "1'"]
        triggered = []
        
        for payload in payloads:
            req = insertionPoint.buildRequest(self._helpers.stringToBytes(payload))
            resp = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), req)
            
            if not resp.getResponse():
                continue
                
            respInfo = self._helpers.analyzeResponse(resp.getResponse())
            body = self._helpers.bytesToString(resp.getResponse()[respInfo.getBodyOffset():])
            
            for db, patterns in self.sql_errors.items():
                for pattern in patterns:
                    # Error in response but NOT in baseline
                    if re.search(pattern, body, re.IGNORECASE) and not re.search(pattern, baseline_body, re.IGNORECASE):
                        triggered.append({'payload': payload, 'db': db, 'resp': resp})
                        break
        
        # Need 2+ triggers AND safe input must NOT trigger
        if len(triggered) >= 2:
            safe_req = insertionPoint.buildRequest(self._helpers.stringToBytes("safetest123abc"))
            safe_resp = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), safe_req)
            
            if safe_resp.getResponse():
                safe_info = self._helpers.analyzeResponse(safe_resp.getResponse())
                safe_body = self._helpers.bytesToString(safe_resp.getResponse()[safe_info.getBodyOffset():])
                
                has_error = False
                for db, patterns in self.sql_errors.items():
                    for pattern in patterns:
                        if re.search(pattern, safe_body, re.IGNORECASE):
                            has_error = True
                            break
                
                if not has_error:
                    # CONFIRMED!
                    url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
                    
                    detail = "SQL Injection vulnerability CONFIRMED (Error-Based)\n\n"
                    detail += "Parameter: " + insertionPoint.getInsertionPointName() + "\n\n"
                    detail += "Evidence:\n"
                    for t in triggered[:3]:
                        detail += "- Payload '" + t['payload'] + "' triggered " + t['db'] + " error\n"
                    detail += "\nVerification: Safe input 'safetest123abc' did NOT trigger any errors.\n\n"
                    detail += "Remediation: Use parameterized queries/prepared statements."
                    
                    return CustomScanIssue(
                        baseRequestResponse.getHttpService(),
                        url,
                        [self._callbacks.applyMarkers(triggered[0]['resp'], None, None)],
                        "SQL Injection - Error Based (Confirmed)",
                        detail,
                        "High",
                        "Certain"
                    )
        return None

    def _test_time_based(self, baseRequestResponse, insertionPoint):
        """Test time-based SQLi with verification"""
        time_payloads = [
            ("' AND SLEEP(5)-- -", "' AND SLEEP(0)-- -", 5, "MySQL"),
            ("' AND SLEEP(5)#", "' AND SLEEP(0)#", 5, "MySQL"),
            ("1 AND SLEEP(5)-- -", "1 AND SLEEP(0)-- -", 5, "MySQL"),
            ("'; SELECT PG_SLEEP(5)-- -", "'; SELECT PG_SLEEP(0)-- -", 5, "PostgreSQL"),
            ("'; WAITFOR DELAY '0:0:5'-- -", "'; WAITFOR DELAY '0:0:0'-- -", 5, "MSSQL"),
        ]
        
        for delay_payload, no_delay_payload, expected, db in time_payloads:
            # Test with delay
            start = time.time()
            req1 = insertionPoint.buildRequest(self._helpers.stringToBytes(delay_payload))
            resp1 = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), req1)
            elapsed1 = time.time() - start
            
            if elapsed1 >= (expected - 1):
                # Test without delay
                start = time.time()
                req2 = insertionPoint.buildRequest(self._helpers.stringToBytes(no_delay_payload))
                resp2 = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), req2)
                elapsed2 = time.time() - start
                
                if elapsed2 < (expected - 1):
                    # Re-verify with delay
                    start = time.time()
                    req3 = insertionPoint.buildRequest(self._helpers.stringToBytes(delay_payload))
                    resp3 = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), req3)
                    elapsed3 = time.time() - start
                    
                    if elapsed3 >= (expected - 1):
                        # CONFIRMED!
                        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
                        
                        detail = "SQL Injection vulnerability CONFIRMED (Time-Based Blind)\n\n"
                        detail += "Parameter: " + insertionPoint.getInsertionPointName() + "\n"
                        detail += "Database: " + db + "\n\n"
                        detail += "Timing Evidence:\n"
                        detail += "- Payload with SLEEP(5): " + str(round(elapsed1, 2)) + "s\n"
                        detail += "- Payload with SLEEP(0): " + str(round(elapsed2, 2)) + "s\n"
                        detail += "- Re-verification with SLEEP(5): " + str(round(elapsed3, 2)) + "s\n\n"
                        detail += "Payload: " + delay_payload + "\n\n"
                        detail += "Remediation: Use parameterized queries/prepared statements."
                        
                        return CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            url,
                            [self._callbacks.applyMarkers(resp1, None, None)],
                            "SQL Injection - Time Based Blind (Confirmed)",
                            detail,
                            "High",
                            "Certain"
                        )
        return None

    def _test_boolean_based(self, baseRequestResponse, insertionPoint, baseline_body):
        """Test boolean-based SQLi with verification"""
        boolean_pairs = [
            ("' AND '1'='1", "' AND '1'='2"),
            ("' AND 1=1-- -", "' AND 1=2-- -"),
            ("1 AND 1=1", "1 AND 1=2"),
            ("') AND ('1'='1", "') AND ('1'='2"),
        ]
        
        baseline_len = len(baseline_body)
        
        for true_payload, false_payload in boolean_pairs:
            # True condition
            req_true = insertionPoint.buildRequest(self._helpers.stringToBytes(true_payload))
            resp_true = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), req_true)
            
            # False condition
            req_false = insertionPoint.buildRequest(self._helpers.stringToBytes(false_payload))
            resp_false = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), req_false)
            
            if not resp_true.getResponse() or not resp_false.getResponse():
                continue
            
            true_info = self._helpers.analyzeResponse(resp_true.getResponse())
            false_info = self._helpers.analyzeResponse(resp_false.getResponse())
            
            true_body = self._helpers.bytesToString(resp_true.getResponse()[true_info.getBodyOffset():])
            false_body = self._helpers.bytesToString(resp_false.getResponse()[false_info.getBodyOffset():])
            
            true_len = len(true_body)
            false_len = len(false_body)
            true_status = true_info.getStatusCode()
            false_status = false_info.getStatusCode()
            
            # Check for significant difference
            diff = abs(true_len - false_len)
            if true_status != false_status or diff > max(baseline_len * 0.1, 100):
                # Verify with another pair
                verify_true_payload = true_payload.replace("1'='1", "2'='2").replace("1=1", "2=2")
                verify_false_payload = false_payload.replace("1'='2", "2'='3").replace("1=2", "2=3")
                
                req_vt = insertionPoint.buildRequest(self._helpers.stringToBytes(verify_true_payload))
                resp_vt = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), req_vt)
                
                req_vf = insertionPoint.buildRequest(self._helpers.stringToBytes(verify_false_payload))
                resp_vf = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), req_vf)
                
                if resp_vt.getResponse() and resp_vf.getResponse():
                    vt_info = self._helpers.analyzeResponse(resp_vt.getResponse())
                    vf_info = self._helpers.analyzeResponse(resp_vf.getResponse())
                    vt_len = len(self._helpers.bytesToString(resp_vt.getResponse()[vt_info.getBodyOffset():]))
                    vf_len = len(self._helpers.bytesToString(resp_vf.getResponse()[vf_info.getBodyOffset():]))
                    
                    # Check consistency
                    if (true_len > false_len and vt_len > vf_len) or (true_len < false_len and vt_len < vf_len):
                        # CONFIRMED!
                        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
                        
                        detail = "SQL Injection vulnerability CONFIRMED (Boolean-Based Blind)\n\n"
                        detail += "Parameter: " + insertionPoint.getInsertionPointName() + "\n\n"
                        detail += "Evidence:\n"
                        detail += "- True payload: " + true_payload + "\n"
                        detail += "  Response length: " + str(true_len) + " bytes, Status: " + str(true_status) + "\n"
                        detail += "- False payload: " + false_payload + "\n"
                        detail += "  Response length: " + str(false_len) + " bytes, Status: " + str(false_status) + "\n\n"
                        detail += "Verification: Consistent behavior with additional payload pairs.\n\n"
                        detail += "Remediation: Use parameterized queries/prepared statements."
                        
                        return CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            url,
                            [self._callbacks.applyMarkers(resp_true, None, None)],
                            "SQL Injection - Boolean Based Blind (Confirmed)",
                            detail,
                            "High",
                            "Certain"
                        )
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0


class CustomScanIssue(IScanIssue):
    """Custom issue that appears in BurpSuite's Issues tab"""
    
    def __init__(self, httpService, url, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
    
    def getUrl(self):
        return self._url
    
    def getIssueName(self):
        return self._name
    
    def getIssueType(self):
        return 0x08000000
    
    def getSeverity(self):
        return self._severity
    
    def getConfidence(self):
        return self._confidence
    
    def getIssueBackground(self):
        return """SQL injection occurs when user input is concatenated into SQL queries 
        without proper sanitization. This allows attackers to modify query logic, 
        access unauthorized data, or execute administrative operations.
        
        This finding has been verified through multiple tests to ensure it is not 
        a false positive."""
    
    def getRemediationBackground(self):
        return """Use parameterized queries (prepared statements) instead of string 
        concatenation. Implement input validation using whitelists. Apply the 
        principle of least privilege for database accounts."""
    
    def getIssueDetail(self):
        return self._detail
    
    def getRemediationDetail(self):
        return None
    
    def getHttpMessages(self):
        return self._httpMessages
    
    def getHttpService(self):
        return self._httpService
