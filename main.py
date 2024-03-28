import os

def vulnerable_function(user_input):
    # Example of SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{user_input}'"
    result = os.system(f"sql_execute '{query}'")

if __name__ == "__main__":
    user_input = input("Enter username: ")
    vulnerable_function(user_input)
