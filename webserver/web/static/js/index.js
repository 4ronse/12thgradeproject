'use strict';

let tree = null;
let current = null;
let onFSLoadEventQueue = [];

const addOnFSLoadEventListener = onEvent => onFSLoadEventQueue.push(onEvent);


function load_tree() {
    $.get('/tree')
        .then((v) => {
            tree = makeFS(JSON.parse(v));
            current = tree;
            document.getElementById('loading-div').style.display = 'none';

            for (let handler; handler = onFSLoadEventQueue.pop();) handler(tree);
        }).catch((e) => console.error(e));
}

window.addEventListener('load', () => {
    load_tree();
});

addOnFSLoadEventListener((tree) => {
    const container = document.getElementById('file-dropzone');
    tree.children.forEach(child => {
        let div = child.getDiv();
        container.appendChild(div);

        div.addEventListener('dblclick', () => {
            if (child.isFile) {
                let link = document.createElement('a');
                link.download = child.name;
                link.href = `/download/${child.SHA256}`;
                link.click();
            }
        });
    });
})
