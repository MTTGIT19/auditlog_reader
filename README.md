# auditlog_reader
Python3 script I wrote that parses a large data set into an organized SQL database.
Based on specific values set by the user, the attack vector is matched up and added as a seperate column.

Utilizes sqlite3 to write to a database for further analysis, see SQL_Output.png for an example.

Possible attack vectors include:
1. Directory traversal
2. Apache Vulnerability
3. Suspicious Host
4. Nikto Scanner


![example](https://user-images.githubusercontent.com/89365060/215274009-2ea04fb7-6c15-408e-9394-08d44ab78635.png)
