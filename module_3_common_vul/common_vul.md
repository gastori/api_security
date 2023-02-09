# Common API Vulnerabilities

## Introduction

APIs have become an essential part of modern web development and have opened new possibilities for communication between different systems. However, with the increase in the use of APIs, there has been an increase in security threats. Understanding and preventing common API vulnerabilities is crucial to securing the data being transmitted through APIs. In this module, we will be discussing the ten most common API vulnerabilities, including:

1.	Broken authentication & authorization
2.	Injection attacks (e.g., SQL, script, command)
3.	Broken access control (excessive data exposure, compromised security)
4.	Insufficient logging & monitoring
5.	Cross-Site Request Forgery (CSRF)
6.	Lack of rate-limiting or throttling
7.	Cross-Site Scripting (XSS)
8.	Server-Side Request Forgery (SSRF)
9.	Insecure Direct Object References
10.	Insecure Cryptographic Storage

## Broken authentication & authorization

Broken authentication and authorization refer to security vulnerabilities that occur in the authentication and authorization process of an API. These vulnerabilities can allow unauthorized access to the API, potentially exposing sensitive data or allowing unauthorized actions to be performed.
Broken authentication refers to weaknesses in the authentication process, such as using weak or easily guessable credentials, or not properly verifying the authenticity of a user's credentials. For example, an attacker might be able to exploit a weak authentication mechanism, such as a easily guessable username and password combination, to gain unauthorized access to the API. To prevent broken authentication, it's important to implement strong authentication mechanisms, such as multi-factor authentication or password hashing with salts and enforce password policies that require users to use strong passwords.

Broken authorization refers to weaknesses in the authorization process, such as lack of proper access controls or inadequate privilege escalation controls. For example, an attacker might be able to access sensitive data or perform unauthorized actions if the API does not properly restrict access to sensitive resources or actions. To prevent broken authorization, it's important to implement proper access controls, such as Role-Based access controls, and regularly review and audit access logs to detect any unauthorized access.

Here's a code example to demonstrate broken authentication in Python using Flask:

```python
from flask import Flask, request

app = Flask(__name__)

# Hard-coded credentials for demonstration purposes only
# In a real-world scenario, you would store credentials securely, such as in a hashed form
valid_credentials = {
    "user1": "password1",
    "user2": "password2"
}

@app.route("/login", methods=["POST"])
def login():
    # Get the username and password from the request
    username = request.form["username"]
    password = request.form["password"]

    # Check if the provided credentials are valid
    if username in valid_credentials and valid_credentials[username] == password:
        # Return a success response if the credentials are valid
        return "Login Successful", 200
    else:
        # Return an error response if the credentials are invalid
        return "Invalid Credentials", 401

if __name__ == "__main__":
    app.run()

```
In this example, the API has hard-coded credentials that can easily be exploited by an attacker. To mitigate this vulnerability, the credentials should be stored securely, such as in a hashed form, and the API should implement proper authentication mechanisms to prevent unauthorized access.

## Injection attacks
Injection attacks refer to a class of security vulnerabilities that occur when an attacker can inject malicious code into a system. In the context of APIs, injection attacks can occur when user-supplied data is not properly validated or sanitized before being processed by the API. This can allow an attacker to inject malicious code, such as SQL, script, or command code, that is executed by the API, potentially leading to data theft, data corruption, or unauthorized actions.

### SQL Injection:

SQL injection attacks occur when an attacker can inject malicious SQL code into a system, allowing them to access or modify sensitive data in a database. For example, an API that accepts a user-supplied "username" parameter as part of a SQL query to retrieve user data could be vulnerable to SQL injection if the user-supplied data is not properly validated or sanitized. The attacker could inject malicious SQL code, such as ```'; DROP TABLE users; --```, which would cause the SQL query to drop the "users" table, potentially causing data loss.
### Script Injection:
Script injection attacks occur when an attacker is able to inject malicious script code into a system, allowing them to execute arbitrary code on the client-side. For example, an API that returns user data in a JSON format and includes user-supplied data without proper validation or sanitization could be vulnerable to script injection. The attacker could inject malicious script code, such as ```<script>alert('XSS Attack');</script>```, which would be executed by the client-side as a Cross-Site Scripting (XSS) attack.
### Command Injection:
Command injection attacks occur when an attacker can inject malicious command code into a system, allowing them to execute arbitrary commands on the server-side. For example, an API that accepts a user-supplied "system command" parameter and executes it without proper validation or sanitization could be vulnerable to command injection. The attacker could inject malicious command code, such as ```; rm -rf /```, which would cause the server to execute the command and potentially cause data loss.

Here's a code example to demonstrate SQL injection in Python using Flask and SQLAlchemy:

```python
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)

@app.route("/user", methods=["GET"])
def get_user():
    # Get the username from the request
    username = request.args.get("username")

    # Query the database for the user with the specified username
    user = User.query.filter_by(username=username).first()

    # Return the user data if found
    if user:
        return {"username": user.username, "password": user.password}, 200
    else:
        return "User Not Found", 404

if __name__ == "__main__":
    db.create_all()
    app.run()
```
In this example, the API is vulnerable to SQL injection because the user-supplied ```"username"``` parameter is used directly in a QL query without proper validation or sanitization. An attacker could inject malicious SQL code as the ```"username"``` parameter, with a SQL statement such as ```'; DROP TABLE users; --```.

This would cause the SQL query to drop the ```"users"``` table, potentially causing data loss. To prevent this vulnerability, it's important to validate and sanitize user-supplied data before using it in SQL queries. This can be done using techniques such as parameterized queries or using an ORM (Object-Relational Mapping) tool like SQLAlchemy.

In the code example above, using SQLAlchemy's ```query.filter_by``` method with a user-supplied parameter would result in a parameterized query, protecting against SQL injection.
It's important to note that injection attacks can occur in various forms and through various injection vectors, including HTTP headers, URL parameters, and request bodies, among others. To protect against injection attacks, it's important to validate and sanitize all user-supplied data before processing it, and to follow secure coding practices and stay up to date with the latest security updates and patches.

## Broken access control
Broken access control is a common vulnerability in APIs that can result in excessive data exposure and compromised security. This vulnerability occurs when an API lacks proper controls over who can access what resources and data. In the absence of proper access controls, attackers can gain unauthorized access to sensitive data and potentially exploit it.

For example, consider an API that provides a list of user profiles. In this case, the API should only provide access to the profile information of users who have granted permission to view their information. However, if the API does not have proper access controls, an attacker could easily gain access to all user profiles, regardless of whether they have permission to view the information. If the API does not properly implement access control mechanisms, an attacker could potentially gain unauthorized access to this sensitive data. For example, the attacker might craft a request to the API that bypasses the normal authentication and authorization checks and retrieves the data without proper authorization.

Here's an example code snippet in Python that demonstrates the vulnerability:
```python
from flask import Flask, request

app = Flask(__name__)

@app.route("/api/resources/<resource>", methods=["GET"])
def get_resource(resource):
    # No access control checks are performed
    response = requests.get(f"https://example.com/{resource}")
    return response.json(), response.status_code

if __name__ == "__main__":
    app.run()
```
In this code snippet, the API does not perform any access control checks, allowing anyone who knows the URL to retrieve the requested resource without proper authorization. To mitigate this vulnerability, the code should include proper access control mechanisms, such as authentication and authorization checks, to ensure that only authorized users have access to sensitive resources.

Here's a code snippet in Python that demonstrates how to implement a simple access control mechanism in an API:

```Python
import jwt
from flask import Flask, request

app = Flask(__name__)
secret = "secret_key"

def has_access(user_id, resource):
    # This function checks if the user has permission to access the requested resource
    # In a real-world scenario, this function would check a database or an access control list
    if user_id == 1:
        return True
    else:
        return False

@app.route("/api/resources/<resource>", methods=["GET"])
def get_resource(resource):
    # Get the token from the request header
    token = request.headers.get("Authorization")

    # If the token is missing, return a 401 error
    if not token:
        return {"error": "Unauthorized"}, 401

    # Decode the token to get the user's ID
    try:
        decoded = jwt.decode(token, secret, algorithms=["HS256"])
        user_id = decoded["id"]
    except jwt.exceptions.InvalidTokenError:
        return {"error": "Invalid token"}, 401

    # Check if the user has access to the requested resource
    if not has_access(user_id, resource):
        return {"error": "Forbidden"}, 403

    # Return the requested resource if the user has access
    return {"data": f"Resource {resource}"}, 200

if __name__ == "__main__":
    app.run()
```
In this code snippet, we're using the Flask web framework to implement a simple API. The ```has_access``` function checks if the user has permission to access the requested resource. 

In this example, it returns True if the user ID is 1, and False otherwise. In a real-world scenario, this function would check a database or an access control list to determine if the user has access.

The ```get_resource``` function implements the access control mechanism. It starts by getting the token from the request header and checking if it's missing. If the token is missing, it returns a 401 error. If the token exists, it decodes the token to get the user's ID and checks if the user has access to the requested resource using the ```has_access``` function. If the user does not have access, it returns a 403 error. If the user has access, it returns the requested resource.

## Insufficient logging & monitoring
Insufficient logging and monitoring is a common vulnerability in APIs that can lead to serious security issues. Logging is the process of recording events that occur during the operation of the API, while monitoring is the process of observing the API's performance and behavior over time. Together, these two functions provide valuable information that can be used to detect, diagnose, and prevent security incidents.
For example, if an API does not log access to sensitive resources, it may be difficult to detect unauthorized access. Similarly, if the API does not monitor incoming traffic for suspicious behavior, it may be vulnerable to attacks such as DDoS or brute-force attacks.
An example of the vulnerability of insufficient logging and monitoring could be a scenario where an API does not log or monitor incoming traffic for suspicious behavior. As a result, an attacker is able to launch a DDoS (Distributed Denial of Service) attack on the API, overwhelming its resources and causing it to become unavailable.

Here's an example code snippet in Python that demonstrates the vulnerability:

```Python
from flask import Flask, request

app = Flask(__name__)

@app.route("/api/resources/<resource>", methods=["GET"])
def get_resource(resource):
    response = requests.get(f"https://example.com/{resource}")
    return response.json(), response.status_code

if __name__ == "__main__":
    app.run()
```
In this code snippet, the API does not have any logging or monitoring in place, leaving it vulnerable to attacks such as DDoS.

Without adequate logging and monitoring, the API's administrators may be unaware of the attack until it's too late, potentially causing damage to the API's reputation and user trust. In this case, having proper logging and monitoring in place could have allowed the administrators to detect the attack early and take action to mitigate its impact.

To mitigate this vulnerability, the code should be updated to include logging and monitoring, as shown in the code sample below.

Here's a code snippet in Python that demonstrates how logging and monitoring could be implemented in an API:
```Python
import logging
import requests
from flask import Flask, request

app = Flask(__name__)

logging.basicConfig(filename="api.log", level=logging.INFO)

@app.route("/api/resources/<resource>", methods=["GET"])
def get_resource(resource):
    # Log the request
    logging.info(f"GET request for resource {resource}")

    # Monitor the response time
    start_time = time.time()
    response = requests.get(f"https://example.com/{resource}")
    response_time = time.time() - start_time

    # Log the response time
    logging.info(f"Response time: {response_time:.2f} seconds")

    # Return the response
    return response.json(), response.status_code

if __name__ == "__main__":
    app.run()
```
In this code snippet, we're using the Flask web framework to implement a simple API. We're also using the logging module from the Python Standard Library to log events and the requests library to make HTTP requests.

The ```get_resource``` function logs the incoming GET request and the response time of the request. The log entries are written to a file named api.log using the logging module. The response time is calculated by measuring the time before and after making the request and logging the difference.
By logging and monitoring the API's behavior, we can gain insight into how it's being used, detect potential security issues, and respond quickly to incidents.

## Cross-Site Request Forgery (CSRF)
Cross-Site Request Forgery (CSRF) is a security vulnerability that affects web-based applications and APIs. It occurs when an attacker is able to trick a user into making a malicious request to a website or API, without the user's knowledge or consent.

In the context of APIs, CSRF attacks can allow an attacker to manipulate an API request in such a way that it appears to come from an authenticated user. For example, consider an API that allows a user to transfer funds from one account to another. If the API does not implement proper protection against CSRF attacks, an attacker could potentially craft a malicious request that transfers funds from the user's account to the attacker's account, without the user's knowledge or consent.
To mitigate the risk of CSRF attacks, APIs should implement anti-CSRF measures, such as checking for a unique token in each request, known as a CSRF token. The token should be generated by the server and included in the HTML form that is sent to the client. The client must include the token in all subsequent API requests, allowing the server to verify the authenticity of the request and reject any requests that do not include a valid token.

Here's an example of a Cross-Site Request Forgery (CSRF) vulnerability:

    Consider a website that allows users to transfer funds from one account to another. The website provides a form for users to enter the recipient's account number and the amount to be transferred. When the form is submitted, the website makes an API request to transfer the funds. However, the website does not implement proper protection against CSRF attacks, making it vulnerable to exploitation. An attacker could craft a malicious web page that contains the same form and makes a request to the same API endpoint. If a user visits the malicious web page, the attacker can trick the user into making a request to transfer funds from the user's account to the attacker's account, without the user's knowledge or consent.

    In this scenario, the attacker is able to bypass the website's authentication mechanism and make unauthorized API requests, all because the website did not implement proper protection against CSRF attacks. This demonstrates the importance of implementing anti-CSRF measures, such as including a unique token in each request, to protect against this type of vulnerability.

Here's a code snippet in Python that demonstrates a simple example of a Cross-Site Request Forgery (CSRF) vulnerability:
```Python
from flask import Flask, request

app = Flask(__name__)

@app.route("/api/transfer_funds", methods=["POST"])
def transfer_funds():
    # Transfer funds
    # ...
    
    return "Funds transferred successfully", 200

if __name__ == "__main__":
    app.run()
```
In this code snippet, the API provides a endpoint to transfer funds without any protection against CSRF attacks. If a malicious web page were to make a request to this endpoint, it could transfer funds from the user's account to the attacker's account, without the user's knowledge or consent.
This demonstrates the importance of implementing anti-CSRF measures, such as checking for a unique token in each request, in order to prevent unauthorized API requests from being processed.

Here's a code snippet in Python that demonstrates the implementation of CSRF protection in an API:
```Python
from flask import Flask, request

app = Flask(__name__)
app.config["SECRET_KEY"] = "secretkey"

@app.route("/api/transfer_funds", methods=["POST"])
def transfer_funds():
    # Check for CSRF token in request
    if request.form.get("csrf_token") != request.cookies.get("csrf_token"):
        return "CSRF token missing or invalid", 400
    
    # Transfer funds
    # ...
    
    return "Funds transferred successfully", 200

if __name__ == "__main__":
    app.run()
```
In this code snippet, the API implements CSRF protection by checking for a CSRF token in each request. If the token is missing or invalid, the API returns an error response. If the token is present and valid, the API proceeds with the request to transfer funds. This helps ensure that only legitimate requests are processed, reducing the risk of unauthorized API requests.

## Lack of rate-limiting or throttling
Rate-limiting or throttling is a security measure that controls the rate at which API requests are processed, in order to prevent abuse or overloading of the API. Lack of rate-limiting or throttling can lead to a number of security and performance issues.

For example, without rate-limiting, an attacker could make an excessive number of requests to an API endpoint in a short period of time, potentially overwhelming the API and causing it to crash. This type of attack is known as a Denial of Service (DoS) attack. Additionally, an attacker could exploit vulnerabilities in an API by making a large number of requests in a short period of time, allowing the attacker to launch an effective attack without triggering any alarm bells.

In order to prevent these types of attacks, it is important to implement rate-limiting or throttling mechanisms in an API. This can be achieved by setting limits on the number of requests that can be made from a single IP address or client in a given period of time, or by using other methods such as token-bucket algorithms or leaky bucket algorithms. By implementing these measures, an API can ensure that it remains available and responsive, even in the face of a potential attack.

In addition to improving security, rate-limiting can also help to conserve system resources and improve overall performance. By limiting the rate at which requests are processed, an API can ensure that it is able to process requests efficiently, without being bogged down by excessive traffic. This can help to improve the overall user experience, as well as prevent issues such as slow response times or timeouts.

Here's a code snippet in Python that demonstrates how you could implement a simple rate-limiting mechanism using a dictionary to keep track of the number of requests made by each client:
```Python
from flask import Flask, request

app = Flask(__name__)

# Dictionary to keep track of the number of requests made by each client
request_counter = {}

# Maximum number of requests allowed per client
MAX_REQUESTS_PER_CLIENT = 100

@app.route("/api/endpoint", methods=["GET"])
def endpoint():
    client_ip = request.remote_addr
    
    # Check if the client has exceeded the maximum number of allowed requests
    if client_ip in request_counter and request_counter[client_ip] >= MAX_REQUESTS_PER_CLIENT:
        return "Too many requests, try again later", 429
    
    # Increment the number of requests made by this client
    if client_ip in request_counter:
        request_counter[client_ip] += 1
    else:
        request_counter[client_ip] = 1
    
    # Process the request
    # ...
    
    return "Request processed successfully", 200

if __name__ == "__main__":
    app.run()
```
In this code snippet, the API keeps track of the number of requests made by each client, using the client's IP address as a key in the request_counter dictionary. If a client makes more than **MAX_REQUESTS_PER_CLIENT** requests, the API will return a **"Too many requests, try again later"** error, with a HTTP status code of **429** (Too Many Requests). This will prevent the client from making further requests until a later time.

Of course, this is just a simple example and in a real-world scenario you would likely want to implement a more sophisticated rate-limiting mechanism, taking into account factors such as time windows, burst limits, and client identity. However, this code snippet should give you a starting point for implementing rate-limiting in your own API.

Here's a code snippet in Python that demonstrates how you could implement a more sophisticated rate-limiting mechanism using a rate-limiting library such as Flask-Limiter:
```Python
from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Initialize Flask-Limiter with the Flask app
limiter = Limiter(app, key_func=get_remote_address)

# Set the rate limit for all endpoints to 100 requests per hour
limiter.limit("100/hour")

@app.route("/api/endpoint", methods=["GET"])
def endpoint():
    # Process the request
    # ...
    
    return "Request processed successfully", 200

if __name__ == "__main__":
    app.run()
```
In this code snippet, Flask-Limiter is initialized with the Flask app using the Limiter class. The ```key_func``` argument is set to ```get_remote_address```, which returns the client's IP address, so that rate-limiting is applied per client IP. The rate limit for all endpoints is set to 100 requests per hour using the ```limiter.limit``` decorator.

If a client makes more than 100 requests within an hour, Flask-Limiter will automatically return a "Too Many Requests" error, with a HTTP status code of 429 (Too Many Requests). The rate-limiting logic is handled by Flask-Limiter, so you don't have to write any additional code to enforce the rate limit.

You can also set different rate limits for different endpoints, or apply rate-limiting to specific routes based on user roles or other criteria. Flask-Limiter provides a flexible and powerful rate-limiting solution that can be tailored to your specific requirements.

## Cross-Site Scripting (XSS)
Cross-Site Scripting (XSS) is a type of vulnerability that allows an attacker to inject malicious code into a web page viewed by other users. The injected code can be used to steal sensitive information, such as login credentials or personal information, or to perform unauthorized actions, such as making unauthorized purchases or posting spam messages. XSS attacks are typically carried out by exploiting vulnerabilities in the way that web applications handle user input.

In an XSS attack, an attacker crafts a malicious payload and embeds it in a URL, a form input, or a cookie. When the payload is executed by a user's web browser, it can execute arbitrary code and access sensitive information stored in the user's browser, such as session tokens or saved credentials.

To mitigate the risk of XSS attacks, it's important to validate and sanitize all user-supplied input before it is displayed on a web page. For example, any special characters, such as angle brackets or ampersands, should be escaped or removed, so that they are not interpreted as HTML tags or entities. In addition, it's a good idea to implement a Content Security Policy (CSP) that restricts the types of content that can be loaded into a web page, and to use the HTTP-only and secure flags on cookies to prevent them from being accessed by malicious scripts.

Here's an example of a vulnerable Python Flask application that is susceptible to XSS attacks:
```Python
from flask import Flask, request

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    # Get the user's name from the query string
    name = request.args.get("name")

    # Render the template with the user's name
    return f"Hello, {name}!", 200

if __name__ == "__main__":
    app.run()
```
In this code snippet, the user's name is retrieved from the query string using ```request.args.get("name")``` and is then rendered in the template without any validation or sanitization. 

This makes the application vulnerable to XSS attacks, as an attacker could craft a malicious payload that includes HTML or JavaScript code, and embed it in the name parameter. When the payload is executed by a user's web browser, it could execute arbitrary code or steal sensitive information.

To mitigate this vulnerability, it's important to validate and sanitize all user-supplied input before it is displayed in a web page. You can do this by using the ```escape()``` function from the html module.

Here's an example of how you could escape user input in a Python Flask application using the built-in escape() function from the html module:
```Python
from flask import Flask, request
from html import escape

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    # Get the user's name from the query string
    name = request.args.get("name")

    # Escape the name to prevent XSS attacks
    escaped_name = escape(name)

    # Render the template with the escaped name
    return f"Hello, {escaped_name}!", 200

if __name__ == "__main__":
    app.run()
```
In this code snippet, the user's name is retrieved from the query string using ```request.args.get("name")```. The ```escape()``` function is then used to escape the name, which prevents any malicious payloads from being interpreted as HTML tags or entities. Finally, the escaped name is rendered in the template, which is returned to the client.

By validating and sanitizing user input, you can significantly reduce the risk of XSS attacks, and ensure that your web applications remain secure and usable for your users.

## Server-Side Request Forgery (SSRF)
Server-Side Request Forgery (SSRF) is a vulnerability that occurs when an application makes an unintended request to a server, allowing attackers to execute arbitrary requests on behalf of the vulnerable application.

The vulnerability arises when the application relies on user-supplied input to determine the target of an HTTP request. If the application does not validate or sanitize the input properly, an attacker can craft a malicious payload that triggers the application to make a request to a server of the attacker's choice.

For example, consider a simple Python Flask application that fetches an image from a URL and displays it to the user:
```Python
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    # Get the URL from the query string
    url = request.args.get("url")

    # Fetch the image from the URL
    response = requests.get(url)

    # Render the image
    return response.content, 200

if __name__ == "__main__":
    app.run()
```
In this code snippet, the URL of the image to be fetched is retrieved from the query string using ```request.args.get("url")```. If the application does not validate the URL, an attacker could craft a malicious payload that triggers the application to make a request to a server of the attacker's choice.

To mitigate SSRF vulnerabilities, it is important to validate and sanitize all user-supplied input before using it to determine the target of an HTTP request. You should also be cautious about relying on external services, as they may not be trustworthy or secure. Additionally, you can limit the scope of the network that the application is allowed to make requests to, so that it cannot reach sensitive or privileged servers. 

Here is an example of how to mitigate SSRF vulnerabilities in the code sample from before:
```Python
from flask import Flask, request
import requests
import re

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    # Get the URL from the query string
    url = request.args.get("url")

    # Validate the URL to ensure it is a valid image URL
    if not re.match(r"^https?://.+\.(jpg|jpeg|png|gif)$", url):
        return "Invalid URL", 400

    # Fetch the image from the URL
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return "Error fetching URL", 500

    # Render the image
    return response.content, 200

if __name__ == "__main__":
    app.run()
```
In this code snippet, we added validation to the URL before making the request. The ```re.match``` function is used to ensure that the URL starts with "http://" or "https://", followed by any number of characters, followed by a dot, followed by one of the following image file extensions: "jpg", "jpeg", "png", or "gif".

We also added error handling to the code to ensure that the application gracefully handles any exceptions that may occur when fetching the image. If the request times out or returns a non-200 status code, the application will return an appropriate error message to the user.
This is just one example of how to mitigate SSRF vulnerabilities in an application. The specific steps required to mitigate SSRF will depend on the specific use case and architecture of the application.

## Insecure Direct Object References
Insecure Direct Object References (IDOR) is a vulnerability that occurs when an application provides direct access to an object, such as a file, database record, or user account, based on user-supplied input. This can allow attackers to bypass the intended access controls and access sensitive information or perform unauthorized actions.

For example, consider an application that displays a user's profile information when they access the URL http://example.com/profile?user_id=123. 

If the user_id parameter is not properly validated, an attacker could modify the value to access other users' profiles by changing the value to ```user_id=456``` or ```user_id=789```.

To mitigate IDOR vulnerabilities, it is important to properly validate user-supplied input to ensure that it falls within a set of allowed values. Additionally, it is best practice to use a unique identifier that is not easily guessable or enumerable, such as a randomly generated identifier, to avoid exposing sensitive information through direct object references.

Here is a simple example of a Python function that validates user input to prevent IDOR vulnerabilities:
```Python
def view_profile(user_id):
    # Validate the user_id to ensure it is an integer
    try:
        user_id = int(user_id)
    except ValueError:
        return "Invalid user_id", 400

    # Retrieve the user's profile information from the database
    user = get_user_by_id(user_id)
    if not user:
        return "User not found", 404

    # Return the user's profile information
    return user
```
In this code snippet, the ```view_profile``` function takes a ```user_id``` parameter, validates that it is an integer, retrieves the user's profile information from the database, and returns it. If the ```user_id``` is not a valid integer or if the user is not found in the database, the function returns an error message. 

This simple validation can help prevent IDOR vulnerabilities by ensuring that the user_id parameter is within the set of allowed values.

## Insecure Cryptographic Storage
Insecure Cryptographic Storage is a vulnerability that occurs when sensitive information, such as passwords, credit card numbers, or other confidential data, is not stored in an encrypted format. This can result in sensitive information being disclosed if an attacker gains access to the database or data storage system.

For example, consider an application that stores passwords in a database as plain text. If an attacker were to gain access to the database, they would be able to see the passwords in clear text, making it easier for them to launch further attacks.

To mitigate Insecure Cryptographic Storage vulnerabilities, it is important to store sensitive information in an encrypted format, using a secure encryption algorithm such as AES or RSA. Additionally, it is best practice to use a unique, random salt for each password, to ensure that even if two users have the same password, their encrypted passwords will be different, making it more difficult for attackers to launch dictionary attacks.

Here is a simple example of a Python function that stores a password securely using the bcrypt library:
```Python
import bcrypt

def store_password(password):
    # Generate a salt using bcrypt
    salt = bcrypt.gensalt()

    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    # Store the hashed password in the database
    store_hashed_password_in_database(hashed_password)
```
In this code snippet, the ```store_password``` function takes a plain text password as input, generates a salt using ```bcrypt```, hashes the password using the salt, and stores the hashed password in the database. 

This helps prevent Insecure Cryptographic Storage vulnerabilities by ensuring that the password is stored in an encrypted format, making it more difficult for attackers to gain access to sensitive information.

# Conclusion
In conclusion, API security is crucial in ensuring the protection of sensitive information and the overall integrity of applications. The common API vulnerabilities, such as Broken authentication and authorization, Injection attacks, Broken access control, Insufficient logging and monitoring, Cross-Site Request Forgery, Lack of rate-limiting or throttling, Cross-Site Scripting, Server-Side Request Forgery, Insecure Direct Object References, and Insecure Cryptographic Storage, are just a few examples of the security challenges that developers must consider when designing and implementing APIs.

It is important for developers to understand these vulnerabilities and take proactive steps to mitigate them. This can involve using secure authentication and authorization mechanisms, properly validating user inputs, using encryption to store sensitive information, implementing proper logging and monitoring, and applying rate-limiting and throttling to control the number of requests to the API.

Overall, investing in API security is crucial in ensuring the success and longevity of applications. By staying informed about the common API vulnerabilities and taking proactive steps to mitigate them, developers can help ensure that their APIs are secure and can withstand attacks.

<br> <br>
<p align="center">
    <img alt="module 2" src="images/mod-3.PNG" width="500"/>    
</p>

<p align="center">
    📖 <b><a href="https://github.com/gastori/api_security/raw/main/module_3_common_vul/pptx/mod-3.pptx">PowerPoint Deck</a></b> 
</p>

<p align="center">
    📖 <b><a href="https://youtu.be/uP2ORcB5iV8">Module 3 Video</a></b>
</p>

<p align="center">
    👋<b><a href="https://www.linkedin.com/in/giulioastori">Follow me on Linkedin</a></b> 
</p>

<p align="center">
    👋<b><a href="https://twitter.com/AstoriGiulio">Follow me on Twitter</a></b> 
</p>


