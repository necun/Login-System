
# Login System Project

Welcome to the **Login System Project**! This project offers a robust authentication system designed to provide secure access management for applications. To get started, you'll need to follow a series of setup steps to prepare your environment, install necessary databases, and run the project on your local machine. This guide will assist you through each step of the process.

## Prerequisites

Ensure the following software is installed on your machine:

- **MySQL Database Management System**: For storing user data.
- **Redis Database**: For cache management to enhance performance.

## Environment Setup

### 1. MySQL Database Setup

First, set up your MySQL database:

- **Install MySQL DBMS** on your machine if it's not already installed.
- **Create a New Database**: Open MySQL and execute the following command to create a new database named `renote_login_sql_db`.

  ```sql
  CREATE DATABASE renote_login_sql_db;
  ```

- **Create the Users Table**: Inside the newly created database, run the following SQL command to create a `users` table with specific columns:

  ```sql
  USE renote_login_sql_db;

  CREATE TABLE users (
      user_id INT AUTO_INCREMENT PRIMARY KEY,
      application_id VARCHAR(255),
      client_id VARCHAR(255),
      username VARCHAR(255) NOT NULL,
      password VARCHAR(255) NOT NULL,
      First_Name VARCHAR(255),
      Last_Name VARCHAR(255),
      email VARCHAR(255) UNIQUE NOT NULL
  );
  ```

### 2. Redis Database Installation

- **Download and install the Redis database** for efficient cache management.

## Project Setup

To get the project up and running on your local machine, follow these steps:

### 1. Clone the Repository

```bash
git clone https://github.com/necun/Login-System.git
```

### 2. Switch to the Correct Branch

Navigate to the project directory and switch to the `Error_fixex` branch:

```bash
git checkout Error_fixex
```

### 3. Activate the Project Environment

Navigate to the project's environment scripts and activate the environment:

- **Windows**:

  ```cmd
  cd loginenv/scripts
  activate.bat
  ```

- **Linux/Mac**:

  ```bash
  cd loginenv/scripts
  source activate
  ```

### 4. Run the Application

With the environment activated, run `python app.py` from the project's root directory. The application will be available at `http://127.0.0.1:5000`.

## Accessing the Application

Open your preferred web browser and navigate to `http://127.0.0.1:5000` to access the Login System application.

## Support

Encountering issues or have questions? Feel free to open an issue on the GitHub repository page for support.
