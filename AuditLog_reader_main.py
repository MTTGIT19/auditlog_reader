import sqlite3

# Create SQL Table
con = sqlite3.connect("pyMODSEC_LOGS.db")
cur = con.cursor()
cur.execute("CREATE TABLE Modsec_logs(id, URL_Line, Attack_Vector)")

# Upload logs, can analyze individual files or all files
Doc1 = "pathway_here/modsec_audit.log"
Doc2 = "pathway_here/modsec_audit.log.1"
Doc3 = "pathway_here/modsec_audit.log.2"
all_logs = (Doc1, Doc2, Doc3)

# First looks for "-B--" generates flag, then searches for more specific information
# First set of options include GET,POST,PUT, or OPTIONS keywords.
# Second set of options include specific flags under -B--
# Writes results to SQL table
for docs in all_logs:
    with open(docs) as f:
        for line in f:
            if "-B--" in line:
                id = line
                attkvec = None
            elif "GET" in line and id:  # Looks for suspicious flags, finds flags and prints possible attkvec(flag) to column, otherwise NULL
                    if "../../" in line and id:
                        attkvec= "Directory Traversal"  
                        cur.execute("INSERT INTO Modsec_logs (id, URL_Line, Attack_Vector) VALUES(?, ?, ?)", (id, line, attkvec))
                        attkvec = None
                    if "%2e%2e" in line and id:
                        attkvec= "Directory Traversal"  
                        cur.execute("INSERT INTO Modsec_logs (id, URL_Line, Attack_Vector) VALUES(?, ?, ?)", (id, line, attkvec))
                        attkvec = None
                    if "rfiinc.txt" in line and id:
                        attkvec = "Directory Traversal"
                        cur.execute("INSERT INTO Modsec_logs (id, URL_Line, Attack_Vector) VALUES(?, ?, ?)", (id, line, attkvec))
                        attkvec = None
                        id = None
                    if ".htaccess" in line and id:
                        attkvec = "Apache Vulnerability"
                        cur.execute("INSERT INTO Modsec_logs (id, URL_Line, Attack_Vector) VALUES(?, ?, ?)", (id, line, attkvec))
                        attkvec = None
                        id = None
            elif "POST" in line and id:
                    attkvec = None
                    cur.execute("INSERT INTO Modsec_logs (id, URL_Line, Attack_Vector) VALUES(?, ?, ?)", (id, line, attkvec))
                    id = None
                    attkvec = None
            elif "PUT" in line and id:
                    attkvec = None
                    cur.execute("INSERT INTO Modsec_logs (id, URL_Line, Attack_Vector) VALUES(?, ?, ?)", (id, line, attkvec))
                    id = None
                    attkvec = None
            elif "OPTIONS" in line and id:
                    attkvec = None
                    cur.execute("INSERT INTO Modsec_logs (id, URL_Line, Attack_Vector) VALUES(?, ?, ?)", (id, line, attkvec))
                    id = None
                    attkvec = None
            elif "zulu.lan" in line and id:
                    attkvec = "Suspicious host"
                    cur.execute("INSERT INTO Modsec_logs (id, URL_Line, Attack_Vector) VALUES(?, ?, ?)", (id, line, attkvec))
                    id = None 
                    attkvec = None
            elif "Nikto" in line and id:
                    attkvec = "Nikto Scanner"
                    cur.execute("INSERT INTO Modsec_logs (id, URL_Line, Attack_Vector) VALUES(?, ?, ?)", (id, line, attkvec))
                    id = None
                    attkvec = None
con.commit()

# Close database          
con.close()