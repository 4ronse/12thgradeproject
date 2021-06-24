import webserver
from pathlib import Path

app = webserver.create_app()

if __name__ == '__main__':
    webserver_folder = Path(__file__).parent / 'webserver'
    cert_path = webserver_folder / 'cert.pem'
    key_path = webserver_folder / 'key.pem'
    ssl_context = None if webserver.Config.NO_SSL else (str(cert_path.absolute()), str(key_path.absolute()))

    host = webserver.Config.HOST
    port = webserver.Config.PORT_NO_SSL if ssl_context is None else webserver.Config.PORT_SSL

    webserver.socketio.run(app, debug=True, ssl_context=ssl_context, host=host, port=port)
