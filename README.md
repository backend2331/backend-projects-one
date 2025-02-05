TASK MANAGEMENT API
This is a simple Task Management API built with Express.js and MySQL. It allows users to register, log in, and manage tasks with role-based access control. The API provides authentication via JWT (JSON Web Token) and supports CRUD operations for task management.


FEATURES
User Registration & Login: Users can register with a username, password, and role (user/admin), and log in to obtain a JWT token for authentication.

TASK MANAGEMENT: Authenticated users can create, view, update, and delete tasks. Each task is linked to a user and includes a title, description, and status (pending, in-progress, completed).

ROLE-BASED ACCESS CONTROL: The API ensures that only users with appropriate roles (admin or user) can access specific resources.


PURPOSE
This API serves as a basic task management system where users can track and manage their tasks. It is designed to demonstrate authentication, authorization, and CRUD operations.



DATABASE CREATION
 Create a MySQL database (e.g., test).
 Run the database creation script to set up the required tables and sample data.
 Update the .env file with your database credentials(example : DB_HOST=localhost, DB_USER=root, ...)


 
 Testing the API
 Test the API endpoints using curl, please refer to the (API Testing Guide) file in this repository

The guide includes:
 A User registration and login commands
 Creating, updating, viewing, and deleting tasks
 Token usage for authentication and authorization