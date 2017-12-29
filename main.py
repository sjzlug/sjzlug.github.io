from flask import Flask

app = Flask(__name__)


@app.route('/')
def root():
    pass


@app.route('/reg')
def reg():
    pass


@app.route('/login')
def login():
    pass


@app.route('/logout')
def logout():
    pass


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8888, debug=True)
