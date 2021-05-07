class ContextMenuItem {
    #self;
    #i;
    #span;

    #_text;
    #_icon;
    #_onclick;

    constructor(data) {
        let div = document.createElement('div');
        let i = document.createElement('i');
        let span = document.createElement('span');

        this.#self = div;
        this.#i = i;
        this.#span = span;

        div.classList.add('context-menu-item');
        div.append(i, span);

        this.setText(data['text']);
        this.setIcon(data['icon']);
        this.setOnClick(data['onclick']);
    }

    setText(text) {
        this.#_text = text;
        this.#span.innerText = text;
    }

    setIcon(icon) {
        if (this.#_icon !== undefined) {
            Object.entries(this.#_icon).forEach(([k, v]) => {
                this.#self.classList.remove(v);
            });
        }

        this.#_icon = icon;
        this.#i.classList.add(icon['name'], icon['style']);
    }

    setOnClick(onclick) {
        if (this.#_onclick !== undefined) {
            this.#self.removeEventListener('click', this.#_onclick);
        }

        this.#_onclick = onclick;
        this.#self.addEventListener('click', onclick);
    }

    get div() {
        return this.#self;
    }
}

class ContextMenu {
    static #menus;

    #items;
    #self;
    #attach;
    #active;

    constructor(priority = 0, items = [], attach = document) {
        let div = document.createElement('div');
        div.id = 'context-menu';

        this.#self = div;
        this.priority = priority;
        this.#attach = attach;
        this.#active = false;
        this.onmenu = (menu, e) => {}

        items.forEach(item => this.addItem(item));

        // ContextMenu.#menus.push(this);
    }

    addItem(item) {
        this.#self.appendChild(item.div);
    }

    import() {
        const attach = this.#attach;

        attach.addEventListener('contextmenu', (e) => {
            e.returnValue = false;
            let self = this.#self;

            const screenWidth = window.innerWidth;
            const screenHeight = window.innerHeight;

            let offsetX = e.clientX;
            let offsetY = e.clientY;

            if (offsetX + self.clientWidth > screenWidth)
                offsetX = screenWidth - self.clientWidth;

            if (offsetY + self.clientHeight > screenHeight)
                offsetY = screenHeight - self.clientHeight;

            self.style.top = offsetY + 'px';
            self.style.left = offsetX + 'px';

            self.classList.add('active');

            this.onmenu(this, e);
        });

        document.addEventListener('click', () => {
            this.hide();
        });

        document.body.appendChild(this.#self);
    }

    hide() {
        this.#self.classList.remove('active');
    }

    get isActive() {
        return this.#active;
    }

    get div() {
        return this.#self;
    }

    get items() {
        return this.#items;
    }
}