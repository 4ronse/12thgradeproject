"""
TODO: Implement my own Validator | Perhaps use WTForms (when I actually understand what it is)
"""
import webserver
import sys

app = webserver.create_app()

if __name__ == '__main__':
    debug = '-debug' in sys.argv or webserver.Config.DEBUG
    ssl_context = None if '-nossl' in sys.argv or webserver.Config.NO_SSL else (
        'cert.crt, key.pem')

    app.run(debug=debug, ssl_context=ssl_context)
