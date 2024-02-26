# RESTful NoSQL database in Flask with Auth0 user authorization on Google Cloud Platform

This project implements a NoSQL database that models users, boats, and loads (cargo) hosted on Google Cloud Firestore in Datastore (legacy) mode and deployed on Google App Engine. Users can create an account and log in with Auth0. Users can create boats and loads and modify and delete boats they've created. They can also assign loads to or remove loads from boats they've created. The API specification, including entity attribute validation, is included in [valdemar_project.pdf](https://github.com/MHValdez/CS493-a9-final-project/blob/main/valdemar_project.pdf). A Postman environment and collection unit test suite are also provided.

### Requirements:

#### Tech Stack
- Datastore for database
- API in Node.js or Python 3
- Deployed on Google App Engine

#### Database Model
- User entity
- Non-user entities: 2 minimum
- Relation between non-user entities: 1 minimum
- Relation between user and a non-user entity: 1 minimum
- Resources corresponding to user-bound non-user entities must be protected

#### API
- Must support the following status codes appropriately:
  - 200
  - 201
  - 204
  - 401
  - 403
  - 405
  - 406


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

The URLs on page 1 of the API spec are defunct in the interest of not accidentally getting charged. 🙂
