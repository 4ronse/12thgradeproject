"""
TODO: Implement my own Validator
"""
import webserver
import sys

app = webserver.create_app()

if __name__ == '__main__':
    debug = '-debug' in sys.argv or webserver.Config.DEBUG
    ssl_context = None if '-nossl' in sys.argv or webserver.Config.NO_SSL else ('cret.crt, key.pem')

    app.run(debug=debug, ssl_context=ssl_context)
