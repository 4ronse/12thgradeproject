'use strict';

let tree = null;
let onFSLoadEventQueue = [];

const addOnFSLoadEventListener = onEvent => onFSLoadEventQueue.push(onEvent);


function load_tree() {
    $.get('/tree')
        .then((v) => {
            tree = makeFS(JSON.parse(v));
            document.getElementById('loading-div').style.display = 'none';

            for(let handler; handler = onFSLoadEventQueue.pop();) handler(tree);
        })
        .catch((e) => console.error(e));
}

window.addEventListener('load', () => {
    load_tree();
});

// addOnFSLoadEventListener((tree) => { console.log(tree, 'sus') })