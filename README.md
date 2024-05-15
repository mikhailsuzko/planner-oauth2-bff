# js-oauth2-bff
This service implements the Backend for frontend (BFF) pattern. It receives requests from the frontend application and forwards them to the backend. It also returns a token to the client, performs token refresh operations, and generates the necessary cookies.

This is the "Task Planner" project. The source code for this project is hosted in 4 repositories. The application uses
oauth2 authorization using keycloak. There is a possibility of authorization by login and password, as well as using a
Google account.

**Components:**

1. [Frontend application](https://github.com/mikhailsuzko/planner-angular): This is where the user interface for
   managing tasks is implemented using Angular and typescript.
2. [Back for Frontend (BFF)](https://github.com/mikhailsuzko/planner-oauth2-bff): This application receives tokens from
   keycloack and passes them to the frontend. It also redirects all requests from the frontend application to the
   backend.
3. [Backend](https://github.com/mikhailsuzko/planer-microservices): Built on microservice architecture using Spring
   Cloud, Spring Cloud Config, Api Gateway, Eureka Client and Server, Spring Security, Spring Jpa, Hibernate. The
   project implements a REST Api for processing requests from the client
4. [Properties](https://github.com/mikhailsuzko/Planner-properties): Since the backend application uses Spring Cloud
   Config, all settings are stored in
   a separate repository that can be changed without the need to rebuild the backend application

**Additional Notes:**

- The project uses keycloak for authentication and authorization.
- The frontend application is built with Angular and typescript.
- The backend application is built on microservice architecture using Spring Cloud.
- The project uses a REST Api for processing requests from the client.
- All settings are stored in a separate repository.
