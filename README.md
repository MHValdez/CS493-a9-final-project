# RESTful NoSQL database in Flask with Auth0 user authorization on Google Cloud Platform

This project implements a NoSQL database that models users, boats, and loads (cargo) hosted on Google Cloud Firestore in Datastore (legacy) mode and deployed on Google App Engine. Users can create an account and log in with Auth0. Users can create boats and loads and modify and delete boats they've created. They can also assign loads to or remove loads from boats they've created. The API specification, including entity attribute validation, is included in [valdemar_project.pdf](https://github.com/MHValdez/CS493-a9-final-project/blob/main/valdemar_project.pdf). A Postman environment and collection for testing are also provided.

## Technologies:
- MongoDB
- Google Cloud Platform Firestore, Datastore, App Engine
- Auth0, JWT
- Flask
- Postman

## Demonstrated Proficiencies:
- Cloud deployment
- RESTful APIs
- HTTP request/response
- Data validation
- Document (NoSQL) database design
  - Schema normalization
  - Cascades
- Authorization
- Authentication with middleware

The URLs on page 1 of the API spec are defunct in the interest of not paying for hosting. 🙂
