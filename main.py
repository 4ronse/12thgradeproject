"""
TODO: Implement my own Validator
"""


import webserver

app = webserver.create_app()

if __name__ == '__main__':
    app.run(debug=webserver.Config.DEBUG)
