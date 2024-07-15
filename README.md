# Simple Intrusion Detection System for SQL Injections

- This project is developed to learn about various types of SQL injections and Docker. The project use Flask app to detect SQL injection attempts in queries.


## Setup - TB Added

## How to use - TB added

    ```
        sudo apt update
        sudo apt install docker.io
        sudo systemctl start docker
        sudo systemctl enable docker
        docker build -t sql-injection-detector .
        docker run -p 8080:80 sql-injection-detector
        docker ps
        docker ps -a
        docker logs CONTAINER_ID
    ```

- How to run and 

    ```
        docker build -t sql-injection-detector .
        docker run -p 5000:5000 sql-injection-detector

    ```

- `docker build -t sql-injection-detector .`

## SQL Injection (SQLi) Concepts

- **Band**
    - **In-Band** - The attack and its results are visible in the same channel of communication. In other words, the attacker can see the results of the injection directly in the application's response.
    - **Out of Band** - "Out of Band" SQL injection refers to attacks where the data exfiltration happens through a different channel than the injection itself.It doesn't rely on the same communication channel (like the direct web application interface) to perform the attack and retrieve the information. Instead, it uses different network protocols or features to extract data or interact with external systems. 

- **DNS-Based SQLi**
    - ; EXEC xp_cmdshell('nslookup [a-zA-Z0-9.-]+')
        - This regular expression detects patterns where an SQL command ends (;) followed by an execution of the xp_cmdshell command in Microsoft SQL Server. xp_cmdshell is used to execute command-line processes; here, it's used to run nslookup, a network administration command-line tool for querying the Domain Name System to obtain domain name or IP address mapping.
        - The [a-zA-Z0-9.-]+ pattern captures alphanumeric domain names, which suggests that the attacker might be using nslookup to send results of a query to a controlled DNS server, thus exfiltrating data.
    - EXTRACTVALUE(xmltype('%remote;]>'), '/l')
        - This pattern uses Oracle’s XML handling capabilities where EXTRACTVALUE function is used to extract data as XML and potentially send queries to external XML entities.
        - %remote;]> likely refers to a placeholder for external entities, implying that an attacker could use it to probe external services or extract data via XML External Entity (XXE) attacks.
- **Error-based SQL injection:** 
    - The attacker intentionally inputs data that triggers database errors, which can reveal information about the database structure, table names, or even sensitive data.
    - r"XP_CMDSHELL" - This pattern searches for "XP_CMDSHELL" in the input.XP_CMDSHELL is a system stored procedure in Microsoft SQL Server that allows execution of operating system commands.It's often targeted in SQLi attacks to gain broader system access.

- **HTTP-Based SQLi**
    - LOAD_FILE('http://[a-zA-Z0-9.-]+/[a-zA-Z0-9_.-]+')
        - This pattern is indicative of an SQL injection attempt that uses the LOAD_FILE function, which is designed to read files into MySQL databases. However, this function is being misused to potentially make HTTP requests to external servers by specifying a URL instead of a local file path.The regex captures URLs, indicating that the attacker could be trying to load remote files (possibly malicious or controlled by the attacker) into the database.
    - LOAD DATA INFILE 'http://[a-zA-Z0-9.-]+/[a-zA-Z0-9_.-]+'
        - Similar to LOAD_FILE, this pattern uses LOAD DATA INFILE, a command in MySQL that loads data from a file into a table. The regex captures attempts to misuse this command to load data from HTTP URLs, which is not inherently supported and would typically indicate an attempt to exploit a misconfiguration or vulnerability that allows remote file loading.
- **Order Injection**
    - **First Order Injection** : First Order Injection occurs when the input provided by a user is immediately used by an application to construct a SQL query without proper validation or sanitation.
        - **Union Attack (r'\bunion\s+SELECT\b')**
            - This attack uses the UNION SQL operator to combine the results of two or more SELECT statements into a single result set. The regex pattern looks for the word "union" followed by the word "SELECT", separated by whitespace. The pattern seems to contain a typo with the 'b' after SELECT, which should be \b to assert a word boundary.

        - **Piggybacking (r';')**
            - Piggybacking involves appending additional SQL statements to an existing query using a semicolon (;). This allows an attacker to execute arbitrary SQL commands.

        - **Stored Procedure SQLi (r'EXEC')**
            - This pattern detects the use of EXEC (execute) command in SQL, which is used to execute a stored procedure. Injecting malicious SQL in stored procedure calls can execute unintended database actions.

        - **Alternate Encoding SQLi (r'%27')**
            - This pattern looks for URL-encoded representations of problematic characters, such as %27 which is the URL encoding for a single quote ('). This type of injection tries to bypass basic SQL injection protections by encoding the characters.
    - **Second Order Injection** : TB Added
- **Server Response Blind Based SQL Injection**
    - Blind SQL Injection (SQLi) is a type of attack that asks the database a true or false question and determines the answer based on the application's response. This is used when the database does not output data to the user directly ( when the attacker can't see the direct results of their injection.).
    - **Boolean-Based Blind Injection** : This method involves injecting a statement that is always true (AND 1=1) or always false (AND 1=0) to modify the application's normal response. If the response changes when the condition is altered, the attacker can infer that the injection was successful.
    - **Time-Based Blind Injection** : This attack delays the server's response to confirm the SQL injection vulnerability. It uses functions like SLEEP() (MySQL) or WAITFOR DELAY (SQL Server) to make the database wait for a specified amount of time. If the response is delayed, it indicates that the query is being executed, confirming the vulnerability.
- **Tautology**
    - A tautology is a logical statement that is always true. In the context of SQL injection, a tautology attack aims to inject a condition that is always true into a SQL query, often in the WHERE clause.
        - r"'sors'1'='1": This pattern looks for variations of "OR '1'='1"

- **Union-based SQL injection:** 
    - The attacker uses the UNION SQL operator to combine the results of two or more SELECT statements into a single result set, which is then returned as part of the HTTP response.

    ```
        SELECT column_name(s) FROM table1
        UNION
        SELECT column_name(s) FROM table2;
    ```

## References
1. SQL injection, https://portswigger.net/web-security/sql-injection
2. sql injection from OWASP,https://owasp.org/www-community/attacks/SQL_Injection
3. SQL injection cheat sheet, https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/
