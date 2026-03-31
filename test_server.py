from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def home():
    input_value = request.args.get('input', '')

    # Simulate SQL Injection error
    if "'" in input_value:
        return "SQL syntax error near ''"

    # Simulate XSS reflection
    return f"You searched for: {input_value}"

if __name__ == "__main__":
    app.run(debug=True)