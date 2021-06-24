class MEvent {
    static #handlers = {};

    constructor(name) {
        this.name = name;

        if(!MEvent.#handlers.hasOwnProperty(name))
            MEvent.#handlers[name] = []
    }

    addEventHandler = handler => {
        MEvent.addEventHandler(this.name, handler);
    }

    dispatch(d = null) {
        MEvent.dispatch(this.name, d)
    }

    static addEventHandler = (name, handler) => {
        if(!MEvent.#handlers.hasOwnProperty(name))
            MEvent.#handlers[name] = []

        MEvent.#handlers[name].push(handler);
    }

    static dispatch = (name, d) => {
        if(MEvent.#handlers.hasOwnProperty(name))
            MEvent.#handlers[name].forEach(handler =>{
                handler(d);
            });
    }

    static allHandlers = () => {
        return MEvent.#handlers
    }
}