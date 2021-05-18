WINEVT_SECURITY = "{\"Message\":\"System audit policy was changed.\r\n\r\nSubject:\r\n\t" \
          "Security ID:\t\tS-1-5-21-1331263578-1683884876-2739179494-500\r\n\t" \
          "Account Name:\t\tAdministrator\r\n\tAccount Domain:\t\tWIN-ACL01C4DS88\r\n\t" \
          "Logon ID:\t\t0x372C7\r\n\r\nAudit Policy Change:\r\n\t" \
          "Category:\t\tPolicy Change\r\n\tSubcategory:\t\t" \
          "Filtering Platform Policy Change\r\n\t" \
          "Subcategory GUID:\t{0cce9233-69ae-11d9-bed3-505054503030}\r\n\t" \
          "Changes:\t\tSuccess Added, Failure added\"," \
          "\"Event\":\"<Event xmlns=\'http://schemas.microsoft.com/win/2004/08/events/event\'>" \
          "<System><Provider Name=\'Microsoft-Windows-Security-Auditing\' " \
          "Guid=\'{54849625-5478-4994-a5ba-3e3b0328c30d}\'/>" \
          f"<EventID><random_int></EventID><Version>0</Version><Level>0</Level>" \
          "<Task>13568</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords>" \
          "<TimeCreated SystemTime=\'2019-05-28T09:29:41.443963000Z\'/><EventRecordID>965047" \
          "</EventRecordID><Correlation ActivityID=\'{1115b961-1535-0000-8bbb-15113515d501}\'/>" \
          "<Execution ProcessID=\'556\' ThreadID=\'6024\'/><Channel>Security</Channel>" \
          "<Computer>WIN-ACL01C4DS88</Computer><Security/></System><EventData>" \
          "<Data Name=\'SubjectUserSid\'>S-1-5-21-1331263578-1683884876-2739179494-500</Data>" \
          "<Data Name=\'SubjectUserName\'>Administrator</Data>" \
          "<Data Name=\'SubjectDomainName\'>WIN-ACL01C4DS88</Data>" \
          "<Data Name=\'SubjectLogonId\'>0x372c7</Data>" \
          "<Data Name=\'CategoryId\'>%%8277" \
          "</Data><Data Name=\'SubcategoryId\'>%%13572</Data>" \
          "<Data Name=\'SubcategoryGuid\'>{0cce9233-69ae-11d9-bed3-505054503030}</Data" \
          "><Data Name=\'AuditPolicyChanges\'>%%8449, %%8451</Data></EventData></Event>\"}"

WINEVT_APPLICATION = "{\"Message\":\"The Desktop Window Manager has registered the session port.\",\"Event\":\"<Event " \
                     "xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>" \
                     "<Provider Name='Desktop Window Manager'/><EventID Qualifiers='16384'><random_int></EventID>" \
                     "<Level>4</Level><Task>0</Task><Keywords>0x80000000000000</Keywords><TimeCreated " \
                     "SystemTime='2021-03-26T09:41:26.382493000Z'/><EventRecordID>946</EventRecordID>" \
                     "<Channel>Application</Channel><Computer>vagrant-2016</Computer><Security/></System>" \
                     "<EventData></EventData></Event>\"}"

WINEVT_SYSTEM= "{\"Message\":\"The sppsvc service entered the running state.\",\"Event\":\"<Event " \
                  "xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>" \
                  "<Provider Name='Service Control Manager' Guid='{555908d1-a6d7-4695-8e1e-26931d2012f4}' " \
                  "EventSourceName='Service Control Manager'/><EventID Qualifiers='16384'><random_int></EventID>" \
                  "<Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8080000000000000" \
                  "</Keywords><TimeCreated SystemTime='2021-03-25T15:01:00.656299500Z'/><EventRecordID>3946" \
                  "</EventRecordID><Correlation/><Execution ProcessID='572' ThreadID='652'/><Channel>" \
                  "System</Channel><Computer>vagrant-2016</Computer><Security/></System><EventData>" \
                  "<Data Name='param1'>sppsvc</Data><Data Name='param2'>running</Data><Binary>" \
                  "7300700070007300760063002F0034000000</Binary></EventData></Event>\"}"

WINEVT_SYSMON = "{\"Message\":\"File creation time changed:\r\nRuleName: T1099\r\nUtcTime: " \
                "2021-03-25 15:04:03.302\r\nProcessGuid: {A5A24D70-A630-605C-8C00-000000000F00}\r\nProcessId: " \
                r"2020\r\nImage: C:\\Users\\Administrator\\AppData\\Local\\Programs\\Opera\\74.0.3911.232\\opera.exe" \
                "\r\nTargetFilename: " r"C:\\Users\\Administrator\\AppData\\Roaming\\Opera Software\\Opera Stable" \
                r"\\" "bc0808a3-2f49-487c-8ae3-325cf7658646.tmp\r\nCreationUtcTime: 2021-03-23 07:56:11.597" \
                "\r\nPreviousCreationUtcTime: 2021-03-25 15:04:03.302\",\"Event\":\"<Event " \
                "xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" \
                "<System><Provider Name='Microsoft-Windows-Sysmon' " \
                "Guid='{5770385F-C22A-43E0-BF4C-06F5698FFBD9}'/>" \
                "<EventID><random_int></EventID><Version>5</Version><Level>4</Level><Task>2</Task>" \
                "<Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated " \
                "SystemTime='2021-03-25T15:04:03.320848900Z'/><EventRecordID>4033</EventRecordID>" \
                "<Correlation/><Execution ProcessID='2044' ThreadID='2692'/>" \
                "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>" \
                "<Computer>vagrant-2016</Computer><Security UserID='S-1-5-18'/>" \
                "</System><EventData><Data Name='RuleName'>T1099</Data><Data Name='UtcTime'>2021-03-25 " \
                "15:04:03.302</Data><Data Name='ProcessGuid'>{A5A24D70-A630-605C-8C00-000000000F00}" \
                "</Data><Data Name='ProcessId'>2020</Data><Data Name='Image'>" \
                r"C:\\Users\\Administrator\\AppData\\Local\\Programs\\Opera\\74.0.3911.232\\opera.exe" \
                r"</Data><Data Name='TargetFilename'>C:\\Users\\Administrator\\AppData\\Roaming\\Opera Software\\" \
                r"Opera Stable\\bc0808a3-2f49-487c-8ae3-325cf7658646.tmp</Data><Data Name='CreationUtcTime'>" \
                "2021-03-23 07:56:11.597</Data><Data Name='PreviousCreationUtcTime'>2021-03-25 15:04:03.302" \
                "</Data></EventData></Event>\"}"

WINEVT_WINDOWS_DEFENDER = "{\"Message\":\"Windows Defender scan has started.\r\n \tScan ID: " \
                           "{6E6187EE-21DF-4CC6-B0FA-42E2ADF201DE}\r\n \tScan Type: " \
                           "Antimalware\r\n \tScan Parameters: Quick Scan\r\n \tScan " \
                           r"Resources: \r\n \tUser: VAGRANT-2016\\Administrator" "\"," \
                           "\"Event\":\"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" \
                           "<System><Provider Name='Microsoft-Windows-Windows Defender' " \
                           "Guid='{11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78}'/><EventID><random_int>" \
                           "</EventID><Version>0</Version><Level>4</Level>" \
                           "<Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords>" \
                           "<TimeCreated SystemTime='2021-03-25T15:07:51.586512400Z'/>" \
                           "<EventRecordID>76</EventRecordID><Correlation/>" \
                           "<Execution ProcessID='1856' ThreadID='3960'/>" \
                           "<Channel>Microsoft-Windows-Windows Defender/Operational" \
                           "</Channel><Computer>vagrant-2016</Computer><Security UserID='S-1-5-18'/></System>" \
                           "<EventData><Data Name='Product Name'>%%827</Data>" \
                           "<Data Name='Product Version'>4.10.14393.1198</Data>" \
                           "<Data Name='Scan ID'>{6E6187EE-21DF-4CC6-B0FA-42E2ADF201DE}</Data>" \
                           "<Data Name='Scan Type Index'>1</Data><Data Name='Scan Type'>%%802" \
                           "</Data><Data Name='Scan Parameters Index'>1</Data>" \
                           "<Data Name='Scan Parameters'>%%806</Data>" \
                           "<Data Name='Domain'>VAGRANT-2016</Data><Data Name='User'>Administrator</Data>" \
                           "<Data Name='SID'>S-1-5-21-3914780927-2846412080-4247273094-500</Data>" \
                           "<Data Name='Scan Resources'></Data></EventData></Event>\"}"
