from flask import Flask

import webserver
import sys

app: Flask = webserver.create_app()

if __name__ == '__main__':
    print(app.root_path)
    app.run(debug=1, host='0.0.0.0')
