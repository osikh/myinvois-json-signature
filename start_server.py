from flask import Flask, render_template, jsonify

app = Flask(__name__)

# Route for rendering HTML page
@app.route('/')
def home():
    return render_template('index.html')

# API endpoint returning JSON data
@app.route('/api/greet/<name>')
def greet(name):
    response = {
        "message": f"Hello, {name}!"
    }
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True)
    # print(f"MyInvois JSON Tools: http://localhost:{PORT}")