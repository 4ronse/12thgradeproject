class FSEntry {
    constructor(name, parent) {
        this.name = name;
        this.parent = parent;
    }
}

class Directory extends FSEntry {
    constructor(name, children = [], parent = null) {
        super(name, parent);
        this.children = children;
        children.forEach((child) => this.addChild(child));
    }

    addChild(child) {
        child.parent = this;
        this.children.push(child);
    }
}

class File extends FSEntry {
    getFullPath() {
        let path = '';
        let ptr = this.parent;

        while (ptr !== null) {
            path = ptr.name + path;
            ptr = ptr.parent;
            console.log(ptr);
        }

        return path + `/${this.name}`;
    }

    getHash() {
        return '0x00'
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