from functools import wraps
from flask import session
from flask_login import current_user
from flask_socketio import disconnect, Namespace, emit, join_room
from . import socketio


def authenticated_only(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        if current_user.is_authenticated:
            return f(*args, **kwargs)
        disconnect()
    return decorator


@authenticated_only
@socketio.on('join')
def on_socketio_join(data):
    join_room(str(current_user.id))
    emit('somethingidk', {'data': 'asadfgsfgdhsdfhsdfgsdfgsdfgsdfgsdfgsdfg'}, to=str(current_user.id))

