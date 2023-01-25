# API Blueprint

## Introduction

APIs, or application programming interfaces, are a fundamental part of modern software development. They enable different systems or applications to communicate with each other, allowing clients to access resources from a provider's API endpoint. In this article, we will explore the anatomy of APIs, including the different types, formats, and methods of authentication that are commonly used.

## Types of APIs

APIs come in different types, each with its own set of rules, functions, and purposes. Two of the most common types are RESTful APIs and GraphQL.

RESTful APIs, or Representational State Transfer APIs, use a set of architectural constraints that are based on HTTP methods. They follow the CRUD (Create, Read, Update, Delete) principles and have a uniform interface, client-server architecture, stateless communication, and cacheable responses. RESTful APIs are designed to improve upon the inefficiencies of other older APIs. They rely entirely on the use of HTTP, which makes them more approachable for end-users. RESTful APIs use standard HTTP methods such as GET, POST, PUT, and DELETE to accomplish CRUD operations. The main advantage of RESTful APIs is their simplicity, ease of use, and flexibility. They can be used with any programming language and can be accessed by any client that can make HTTP requests.

GraphQL, short for Graph Query Language, is a specification for APIs that allows clients to define the structure of the data they want to request from the server. GraphQL APIs are query-centric, similar to a database query language like SQL, and store resources in a graph data structure. This allows clients to request exactly the data they need, reducing the amount of data that needs to be sent over the network, and reducing the complexity of the client-side code. GraphQL also uses HTTP, typically depending on a single entry point using the POST method. GraphQL uses three operations within the POST request to interact with GraphQL APIs: query, mutation, and subscription. The query operation is used to retrieve data (read), the mutation operation is used to submit and write data (create, update, and delete), and the subscription operation is used to send data (for read actions) when an event occurs. Subscription allows GraphQL clients to listen to live updates from the server, which is useful in applications that require real-time data.

Both RESTful and GraphQL APIs have their own strengths and best use cases. RESTful APIs are simple, flexible, and widely adopted, making them a good choice for simple use cases and for building simple APIs. GraphQL, on the other hand, is better suited for more complex use cases, where clients need more control over the data they receive, and for building more powerful and flexible APIs. Understanding the differences between the two can help developers choose the right API type for their use case.

## Data Interchange Formats

APIs use several formats to facilitate the exchange of data. Additionally, specifications use these formats to document APIs. Some APIs, like SOAP, require a specific format, whereas others allow the client to specify the format to use in the request and response body. The three common formats that are used in APIs are JSON, XML, and YAML.

JSON (JavaScript Object Notation) is the primary data interchange format used for APIs. It is widely used because it is human-readable and easily parsable by applications. JSON organizes data in a way that is both human-readable and easily parsable by applications; many programming languages can turn JSON into data types they can use. JSON represents objects as key/value pairs separated by commas, within a pair of curly brackets.
XML (Extensible Markup Language) is another format that is commonly used in APIs. It is a markup language that uses tags to define elements and attributes to define properties of those elements. XML is more verbose than JSON and is less commonly used in modern web development.

YAML (YAML Ain’t Markup Language) is another lightweight form of data exchange used in APIs. It was created as a more human- and computer-readable format for data exchange. Like JSON, YAML documents contain key/value pairs. The value may be any of the YAML data types, which include numbers, strings, Booleans, null values, and sequences. YAML is much more readable than JSON. YAML documents begin with --- and end with ... instead of with curly brackets. Also, quotes around strings are optional. Additionally, URLs don’t need to be encoded with backslashes. Finally, YAML uses indentation instead of curly brackets to represent nesting and allows for comments beginning with #.

## Authentication Methods

API keys are unique strings that API providers generate and grant to authorize access for approved consumers. Once an API consumer has a key, they can include it in requests whenever specified by the provider. The provider will typically require that the consumer pass the key in query string parameters, request headers, body data, or as a cookie when they make a request. API keys can be more secure than basic authentication for several reasons. When keys are sufficiently long, complex, and randomly generated, they can be exceedingly difficult for an attacker to guess or brute-force. Additionally, providers can set expiration dates to limit the length of time for which the keys are valid. However, API keys have several associated risks that can be exploited by hackers. Since each API provider may have their own system for generating API keys, hackers may be able to guess or forge API keys by learning about the API consumers. Additionally, API keys may be exposed to the internet in online repositories, left in code comments, intercepted when transferred over unencrypted connections, or stolen through phishing.

Another method of API authentication is using JSON Web Tokens (JWT). JWT is a type of token commonly used in API token-based authentication. The process of acquiring a JWT token consists of the consumer authenticating to the API provider with a username and password, the provider then generates a JWT and sends it back to the consumer, and the consumer then adds the JWT to the Authorization header in all API requests. JWTs consist of three parts, all of which are base64-encoded and separated by periods: the header, the payload, and the signature. The header includes information about the algorithm used to sign the payload, the payload includes data such as the username, timestamp, and issuer, and the signature is the encoded and encrypted message used to validate the token. JWTs are generally secure but can be implemented in ways that will compromise that security. For example, if the token is not encrypted, an attacker could decode the token, tamper with the contents, and send it back to the provider to gain access.

A Hash-based Message Authentication Code (HMAC) is another method of API authentication. It is the primary API authentication method used by Amazon Web Services (AWS). The process of acquiring an HMAC token consists of the provider creating a secret key and sharing it with the consumer. When the consumer interacts with the API, an HMAC hash function is applied to the consumer's API request data and secret key. The resulting hash (also called a message digest) is added to the request and sent to the provider. The provider calculates the HMAC, just as the consumer did, by running the message and key through the hash function, and then compares the output hash value to the value provided by the client. If the provider's hash value matches the consumer's hash value, the consumer is authorized to make the request. If the values do not match, either the client's secret key is incorrect, or the message has been tampered with. The security of the message digest depends on the cryptographic strength of the hash function and secret key. Stronger hash mechanisms typically produce longer hashes.

## Common security weaknesses

APIs, similar to other applications, are not immune to vulnerabilities. Some of the most common security weaknesses that attackers leverage and exploit to hack APIs include:
- Injection attacks: This type of attack occurs when an attacker injects malicious code into an API's input fields, such as SQL injection, where the attacker can gain access to sensitive data stored in the database.
- Insufficient authentication and access control: APIs that do not have proper authentication and access controls in place are vulnerable to unauthorized access and use by attackers.
- Weak or easily guessable API keys: APIs that use easily guessable or weak keys can be easily compromised by attackers.
- Lack of encryption: APIs that do not use encryption to protect sensitive data in transit and storage are vulnerable to eavesdropping and data breaches.
- Broken object-level authorization: APIs that have poor object-level authorization controls can be exploited by attackers to access or manipulate sensitive data.
- Lack of logging and monitoring: APIs that do not log and monitor access and usage are vulnerable to attacks that go unnoticed.
- Inadequate input validation: APIs that do not properly validate input data can be exploited by attackers to inject malicious data and gain unauthorized access.
- Insecure communication: APIs that do not use secure protocols for communication such as HTTPS can be intercepted and manipulated by attackers.
- Lack of API rate limiting: APIs that do not have rate limiting in place can be subject to DDoS attacks and other types of abuse.
- Lack of API versioning: APIs that do not have proper versioning in place can be vulnerable to attacks targeting known vulnerabilities in older versions.
- Lack of API documentation: APIs that lack proper documentation make it harder for developers to understand the intended use of the API and may lead to insecure usage.
- Lack of proper testing: APIs that have not been properly tested are more likely to contain security vulnerabilities.
- Lack of proper API lifecycle management: APIs that are not properly managed throughout their lifecycle can become obsolete and unsecure over time.
Note: It's important to note that this is not an exhaustive list, as new types of attacks and vulnerabilities continue to emerge.

### In conclusion
APIs play an important role in modern software development and come in different types such as RESTful and GraphQL. They use different formats like JSON, XML, YAML to facilitate data exchange. Additionally, APIs use different methods of authentication like API keys, JWT and HMAC to ensure that only authorized users can access the resources. As an API developer or consumer, it is important to understand these different aspects of APIs in order to make informed decisions and ensure the security of the API.

<p align="center">
    <img alt="module 2" src="images/slide1.png" width="500"/>
    
</p>

<p align="center">
    🙌 <b><a href="https://github.com/gastori/api_security/raw/main/module_2_api_bp/pptx/api_bp.pptx">PowerPoint Deck</a></b> 📖
</p>
