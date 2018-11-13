# sqlidetect

## Goal 

Detect potential SQL Injection in containerized microservices enviroment.

## Background

In the trend of containerized micro services, application become more and more modualized (micro services). This also indicates limited data operations will be conducted from application to database for a specific service. This helps narrow down/whitelist the all the benign behavior of SQL statements. 

# Solution

In your test enviroment, full test your microservices data operation, geneated the SQL statement signatures for that particular service as a module, and use the module as detection baseline in production enviroment. 
