# Internship_project
## Overview
This project is a Flask web application that provides user registration, login, account management, and an admin dashboard for managing users. The application implements various security measures including:
- Password hashing with bcrypt
- Google reCAPTCHA for login protection
- Account lockout after multiple failed login attempts
- Protection against SQL injection through parameterized queries

This repository demonstrates a complete user management system built with Python, Flask, MySQL, and modern frontend technologies.

## Features
- **User Registration & Login:** Secure user registration with unique email validation and login protection.
- **User Dashboard:** An interactive dashboard where users can update their account details.
- **Admin Dashboard:** Admin users can view and manage all registered users.
- **Security Measures:** 
  - Hashed passwords using bcrypt.
  - reCAPTCHA integration to mitigate brute force attacks.
  - Account lockout after 5 failed login attempts.
- **Session Management:** Secure session handling using Flask sessions.
- 
## Prerequisites
- Python 3.x
- Flask
- MySQL
- Virtualenv (optional but recommended)

- ## Installation Instructions
1. Clone the repository:
   ```bash
   git clone https://github.com/waitupbozo/Internship_project.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Internship_project
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Set Up a Virtual Environment:
python -m venv venv
# Activate the virtual environment:
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

## Install Dependencies:
pip install -r requirements.txt

## Set Up the MySQL Database:
Log in to your MySQL client and create a database:

CREATE DATABASE flask_app;
USE flask_app;

## Create the users table:
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(200) NOT NULL,
    role VARCHAR(20) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

## Configure Environment Variables:
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your_secret_key_here
MYSQL_HOST=localhost
MYSQL_USER=your_mysql_user
MYSQL_PASSWORD=your_mysql_password
MYSQL_DB=flask_app
RECAPTCHA_SITE_KEY=your_recaptcha_site_key
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key

## Make sure your .gitignore file includes the .env file:
.env

## Run the Application:
flask run

## Access the Application:
Open your browser and navigate to http://127.0.0.1:5000.

## Screenshots:
Screenshots are included in the screenshots folder.

## Challenges Faced & Solutions Implemented
1. Handling Duplicate Registrations
Challenge: Users attempting to register with an email that already exists.
Solution: Implemented a check in the registration route to query the database for existing emails. If found, the system flashes a message and redirects the user to the login page.
2. Securing Login with reCAPTCHA and Account Lockout
Challenge: Preventing brute force attacks and handling multiple failed login attempts.
Solution: Integrated Google reCAPTCHA to verify user interactions and implemented account lockout after 5 failed attempts. Used session variables to track failed attempts and stored lockout time in ISO format.
3. Protecting Sensitive Data
Challenge: Keeping API keys, database credentials, and other sensitive information private.
Solution: Used environment variables stored in a .env file that is excluded from Git version control by adding it to .gitignore. Instructions for configuring these variables are provided in the README.
4. Input Validation and SQL Injection Prevention
Challenge: Ensuring that user inputs do not compromise the system.
Solution: Used parameterized queries with MySQL and performed input validation both client-side and server-side to prevent SQL injection.

## Contributing
Contributions are welcome! If you'd like to contribute, please fork the repository, make your changes, and open a pull request. Make sure to follow the coding guidelines and write tests for any new features.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
