TASK MANAGEMENT API
This is a simple Task Management API built with Express.js and MySQL. It allows users to register, log in, and manage tasks with role-based access control. The API provides authentication via JWT (JSON Web Token) and supports CRUD operations for task management.


FEATURES
User Registration & Login: Users can register with a username, password, and role (user/admin), and log in to obtain a JWT token for authentication.

TASK MANAGEMENT: Authenticated users can create, view, update, and delete tasks. Each task is linked to a user and includes a title, description, and status (pending, in-progress, completed).

ROLE-BASED ACCESS CONTROL: The API ensures that only users with appropriate roles (admin or user) can access specific resources.


PURPOSE
This API serves as a basic task management system where users can track and manage their tasks. It is designed to demonstrate authentication, authorization, and CRUD operations.
