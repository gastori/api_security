# Web Applications 101

Web applications are designed to allow end-user interactivity and are built on the client/server model. The client, typically a web browser, generates requests for resources and sends them to web servers. These servers then send resources back to the client over a network. Examples of web applications include LinkedIn, Facebook, Instagram, Outlook.com, GitHub, etc. They are designed to perform specific functions, such as online shopping, social networking, and email services, to name a few.

One of the key technologies that support web applications is HyperText Transfer Protocol (HTTP). This protocol is responsible for the communication between the client and the server. In this module, we will cover the fundamental aspects of HTTP, including methods such as GET, POST, PUT, DELETE, and more. We will also cover authentication and authorization, as well as common web server databases. Understanding these basics is crucial for using and hacking APIs.

## Idempotent Methods

In HTTP, there are certain methods that are considered idempotent, which means that they can be used to send the same request multiple times without changing the state of a resource on a web server. For example, a GET request for a webpage will always return the same webpage, regardless of how many times the request is sent. This is because the GET method is used to retrieve a resource from the server, and the resource itself will not change. Other idempotent methods include HEAD, PUT, OPTIONS, and DELETE. These methods are considered safe and are typically used for read-only operations.

## Non-Idempotent Methods

On the other hand, non-idempotent methods can dynamically change the results of a resource on a server. These methods include POST, PATCH, and CONNECT. POST is the most commonly used method for changing web server resources and is used to create new resources on a web server. Therefore, if a POST request is submitted multiple times, it will create multiple new resources on the web server. In contrast, if an idempotent method like PUT is requested multiple times, it will overwrite a single resource multiple times. These methods are typically used for operations that can change the state of a resource, such as creating or updating data.

## Stateful and Stateless HTTP

HTTP is a stateless protocol, meaning that the server does not keep track of information between requests. However, for users to have a consistent experience with a web application, the web server needs to remember something about the HTTP session with that client. This is achieved through the use of small text files called cookies, which are stored on the client side. These cookies can store site-specific settings, security settings, and authentication-related information.

While stateful connections allow for a more personalized experience for the user, they also have scaling limitations. The server can only handle as many stateful connections as allowed by its computing resources. To overcome this limitation, stateless communications have been introduced. In stateless communications, the server does not store session information, and every request sent must contain all the necessary information for the web server to recognize that the requestor is authorized to access the given resources. This could include a token or an authorization header. Stateless connections are more scalable, as they do not require the server to maintain a session for each user, but the user experience could be less personalized.

## Anatomy of a URL
A URL, or uniform resource locator, is the address used to locate unique resources on the internet. The components of a URL include the protocol, hostname, port, path, and query parameters.

- The protocol is the set of rules that computers use to communicate. The primary protocols used within a URL are HTTP/HTTPS for web pages and FTP for file transfers.
- The hostname is the domain name of the website, such as www.example.com.
- The port is a number that specifies a communication channel. It is only included if the host does not automatically resolve the request to the proper port. Typically, HTTP communications take place over port 80, HTTPS over port 443, and FTP over port 21.
- The path is the file directory on the web server that points to the location of the web pages and files specified in the URL. It is similar to a filepath used to locate files on a computer.
- The query is an optional part of the URL used to perform functionality such as searching, filtering, and translating the language of the requested information. It starts with a question mark and contains a string that the server is programmed to process. The query parameters are the values that describe what should be done with the given query. These parameters consist of another string to be processed by the web server. A query can contain multiple parameters separated by an ampersand (&).

## HTTP Request and Response
When a client (such as a web browser) wants to request a resource from a server, it sends an HTTP request. The request includes the method, headers, and body.
- The method, also known as the HTTP verb, is used to indicate the desired action to be performed on the resource, such as GET, POST, PUT, DELETE, etc.
- The headers contain additional information about the request, such as the type of content being sent, the client's preferred language, and any authentication credentials.
- The body is the content of the request, such as a form data or a JSON payload.
- When the server receives the request, it sends back an HTTP response. The response includes the status code, headers, and body.
- The status code is a three-digit number that indicates the outcome of the request. Common status codes include 200 OK, 201 Created, 204 No Content, 400 Bad Request, 401 Unauthorized, and 404 Not Found.
- The headers contain additional information about the response, such as the type of content being sent, the server's preferred language, and any authentication credentials.
- The body is the content of the response, such as a webpage or JSON data.
- HTTP Methods
    - HTTP methods, also known as verbs, indicate the desired action to be performed on a resource. The most commonly used methods are:
    - GET: Retrieve a resource from the server. GET requests are idempotent, which means that they can be repeated multiple times without changing the state of the resource.
    - POST: Create a new resource on the server. POST requests are non-idempotent, which means that they can change the state of the resource.
    - PUT: Update an existing resource on the server. PUT requests are idempotent, which means that they can be repeated multiple times without changing the state of the resource.
    - DELETE: Delete a resource from the server. DELETE requests are idempotent, which means that they can be repeated multiple times without changing the state of the resource.

It's important to note that the HTTP method used in a request can affect the outcome of the request. For example, a GET request will retrieve a resource without changing its state, while a POST request will create a new resource.

## Web Server

A web server is a software that handles HTTP requests and responses. It receives requests from clients, such as web browsers, and sends back the appropriate response. The response could be a webpage, an image, or a JSON data, for example.
Web servers can be configured to handle different types of requests. For example, a web server can be configured to handle PHP scripts, which are used to generate dynamic web pages. It can also be configured to handle different types of file extensions, such as .html, .jpg, .mp4, etc.

There are many web servers available, including Apache, Nginx, and IIS. Each of these servers has its own set of features and can be configured differently.
web server can function as both the front-end and back-end for web services.
When a web server functions as the front-end, it receives requests from clients, such as web browsers, and sends back the appropriate response. This response could be a webpage, an image, or a JSON data, for example. The front-end is responsible for handling the user interface and presentation logic of the web service.
When a web server functions as the back-end, it receives requests from the front-end and performs the necessary actions to fulfill the request. This could include interacting with a database to retrieve or store data, performing calculations, or making external API calls. The back-end is responsible for handling the business logic and data processing of the web service.

A web server can also function as both the front-end and back-end by handling both the presentation logic and business logic in the same process. This is known as a full-stack web server.

However, as the complexity and size of the web service increases, it may become more beneficial to separate the front-end and back-end into separate processes and servers. This allows for a clear separation of concerns, better scalability, and improved security.

## Database Layer

The database layer is responsible for storing and retrieving data for web applications. The data can be stored in various types of databases, such as relational databases like MySQL, PostgreSQL, and Oracle, or NoSQL databases like MongoDB, Cassandra, and Redis.
The database layer communicates with the web server through a database management system (DBMS) that acts as an interface between the database and the web server. This allows the web server to send and receive data from the database, such as querying for information or inserting new data.

Web servers and databases often run on different machines to allow:
1.	Scalability: By separating the web server and database onto different machines, it allows for more flexibility in terms of scaling each component separately. If the web server becomes overwhelmed with requests, it can be scaled horizontally by adding more machines. Similarly, if the database becomes overwhelmed with requests, it can be scaled horizontally by adding more machines or vertically by upgrading the hardware.
2.	Performance: By separating the web server and database, it can also improve the performance of the application as a whole. The web server can handle the incoming requests and the database can handle data storage and retrieval, each can handle its own specific task more efficiently.
3.	Security: By separating the web server and database, it can also increase the security of the application. The web server is responsible for handling the incoming requests and the database is responsible for storing sensitive data. By separating these two components, it reduces the attack surface and makes it more difficult for an attacker to access sensitive data.
4.	Maintenance: By separating the web server and database, it allows for more flexibility in terms of maintenance. The web server and database can be updated, backed up, and maintained separately, without affecting the other component.

It's worth noting that there are cases where the web server and database can run on the same machine, especially for small web services. But as the service grows and the traffic increases, it's more secure, reliable, and efficient to separate them into different machines.
Within this context APIs (Application Programming Interfaces) provide a way for different software applications to communicate with each other. They allow one application to access the functionality of another application, without requiring direct access to the code or data. APIs are built on top of web technologies, such as HTTP and web servers, and can be used to access data from a variety of sources, including web services, databases, and cloud services.

In the context of web applications, APIs are a way for the front-end of the web application (e.g. the web browser) to communicate with the back-end of the web application (e.g. the web server and database) in order to retrieve or update data. The front-end sends a request to a specific endpoint on the back-end, and the back-end responds with the requested data.
APIs can be accessed through a variety of methods, including AJAX, JSONP, and CORS, which allow web pages to retrieve data from a server asynchronously and update the page without requiring a full page reload. This allows for a more seamless and efficient user experience, as well as better scalability.

APIs also provide a way for other developers to access the functionality of a web application, without requiring direct access to the code or data. This allows for greater flexibility and reusability, as well as the ability to integrate with other web services and applications.

Overall, APIs are a key component of web development and web services, and they play a crucial role in allowing web applications to communicate with other systems and services.

## Conclusion

In conclusion, web applications rely on several key technologies to function, including the HyperText Transfer Protocol (HTTP), web servers, and databases. Understanding these technologies is crucial for understanding how web applications work and how to use and hack APIs.

HTTP is the protocol used for communication between web browsers and web servers. It is a stateless protocol, which means that the server doesn't keep track of information between requests. However, web applications need to maintain state in order to provide a consistent experience for users, which is achieved through the use of cookies and other stateful methods.
Web servers are software that handle HTTP requests and responses. They can be configured to handle different types of requests and can be used as the front-end or back-end of a web application. Databases are used to store and retrieve data for web applications and communicate with the web server through a database management system.

APIs (Application Programming Interfaces) provide a way for different software applications to communicate with each other. They allow one application to access the functionality of another application, without requiring direct access to the code or data. APIs are built on top of web technologies, such as HTTP and web servers, and can be used to access data from a variety of sources.

In a web application, APIs are used to allow the front-end to communicate with the back-end in order to retrieve or update data. They also provide a way for other developers to access the functionality of a web application, without requiring direct access to the code or data.

To sum up, web applications rely on several technologies to function, including HTTP, web servers, databases and APIs. Understanding these technologies is crucial to understand how web applications work and how to use and hack APIs. Separating the web server and database into different machines can increase scalability, performance and security, but it's not always necessary. APIs are a key component of web development and web services, and they play a crucial role in allowing web applications to communicate with other systems and services.

![Alt text] (images/pptx.png)

![Alt text] (https://github.com/gastori/api_security/blob/main/web_app_101/images/pptx.png)

[PowerPoint Deck Here](https://github.com/gastori/api_security/raw/main/web_app_101/pptx/web_app_101.pptx)


