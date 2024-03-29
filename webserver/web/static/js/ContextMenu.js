class ContextMenuItem {
    #self;
    #i;
    #span;

    #_text;
    #_icon;
    #_onclick;

    /**
     * A Context menu item class
     * @param {json} data File data 
     */
    constructor(data) {
        let div = document.createElement('div');
        let i = document.createElement('i');
        let span = document.createElement('span');

        this.#self = div;
        this.#i = i;
        this.#span = span;

        div.classList.add('context-menu-item', 'row', 'm-0', 'px-0', 'py-1', 'align-self-center');
        i.classList.add('col-1', 'my-auto');
        span.classList.add('col-10', 'my-auto');

        div.append(i, span);

        this.setText(data['text']);
        this.setIcon(data['icon']);
        this.setOnClick(data['onclick']);
    }

    /**
     * Sets item's text
     * @param {string} text 
     */
    setText(text) {
        this.#_text = text;
        this.#span.innerText = text;
    }

    /**
     * Sets item's icon
     * @param {json} icon from FAwesome {name: 'far-download', style: 'fa'}
     */
    setIcon(icon) {
        if (this.#_icon !== undefined) {
            Object.entries(this.#_icon).forEach(([k, v]) => {
                this.#self.classList.remove(v);
            });
        }

        this.#_icon = icon;
        this.#i.classList.add(icon['name'], icon['style']);
    }

    /**
     * Set item click callback
     * @param {function} onclick 
     */
    setOnClick(onclick) {
        if (this.#_onclick !== undefined) {
            this.#self.removeEventListener('click', this.#_onclick);
        }

        this.#_onclick = onclick;
        this.#self.addEventListener('click', onclick);
    }

    /**
     * Create item div
     * @returns {DOMElement}
     */
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

    /**
     * A Context menu class
     * @param {number} priority Context menu's priority
     * @param {list} items List of ContextMenuItem(s)
     * @param {DOMElement} attach DOM element to attach Context Menu to
     */
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

    /**
     * Adds item to context menu
     * @param {ContextMenuItem} item 
     */
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

    /**
     * Hides context menu
     */
    hide() {
        this.#self.classList.remove('active');
    }

    /**
     * Check wether or not the context menu is active
     * @returns {boolean}
     */
    get isActive() {
        return this.#active;
    }

    /**
     * Create div to put in HTML
     * @returns {DOMElement}
     */
    get div() {
        return this.#self;
    }

    /**
     * Returns a list of context menu's items 
     * @returns {ContextMenuItem}
     */
    get items() {
        return this.#items;
    }
}