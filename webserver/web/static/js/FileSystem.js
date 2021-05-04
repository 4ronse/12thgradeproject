async function digestMessage(message) {
  const msgUint8 = new TextEncoder().encode(message);                           // encode as (utf-8) Uint8Array
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);           // hash the message
  const hashArray = Array.from(new Uint8Array(hashBuffer));                     // convert buffer to byte array
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
  return hashHex;
}

class FSEntry {
    constructor(name, parent) {
        this.name = name;
        this.parent = parent;
    }

    get isFile() {
        return false;
    }

    get isDirectory() {
        return false;
    }
}

class Directory extends FSEntry {
    constructor(name, children = [], parent = null) {
        super(name, parent);
        this.children = children;
        children.forEach((child) => this.addChild(child));

    }

    get(what) {
        for (let i = 0; i < this.children.length; i++) {
            const child = this.children[i];
            if(child.name === what) return child;
        }

        return undefined;
    }

    addChild(child) {
        child.parent = this;
        this.children.push(child);
    }

    toString() {
        return `Directory[name: ${this.name}; children: ${this.children.length}]`
    }

    get isDirectory() {
        return true;
    }
}

/*
Object.defineProperty(Directory.prototype, "[]", {
    value: function(id) {
        console.log('a');
        if(typeof id == 'number') return this.children[id];

        this.children.forEach(child => {
            if(
                (child.hasOwnProperty('name') && child.name === id) ||
                (child === id)
            ) return child;
        });
    }
})
 */

class File extends FSEntry {
    #sha256;

    constructor(name, parent) {
        super(name, parent);

        this.#sha256 = '';
        this.#getSHA256(digest => { this.#sha256 = digest; });
    }

    getFullPath() {
        let path = '';
        let ptr = this.parent;

        while (ptr !== null) {
            path = ptr.name + path;
            ptr = ptr.parent;
        }

        return path + `/${this.name}`;
    }

    get SHA256() {
        return this.#sha256;
    }

    #getSHA256(callback) {
        return digestMessage(this.getFullPath()).then(digest => callback(digest));
    }

    toString() {
        return `File[name: ${this.name}; path: ${this.getFullPath()}]`
    }

    get extension() {
        if(this.name.indexOf('.') === -1) return 'bin';
        let splitName = this.name.split('.');

        return splitName[splitName.length - 1];
    }

    get isFile() {
        return true;
    }
}

function makeFS(json, i = 0) {
    let root = new Directory(json['name']);

    json.children.forEach(child => {
        if (child.hasOwnProperty('name')) root.addChild(makeFS(child, i + 1));
        else root.addChild(new File(child, root));
    });

    return root;
}