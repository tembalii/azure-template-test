def execute_command(command):
    # Example of Command Injection vulnerability
    os.system(command)

def display_message(message):
    # Example of Cross-Site Scripting (XSS) vulnerability
    print(f"<script>alert('{message}')</script>")
