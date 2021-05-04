'use strict';

function load_tree() {
    $.get('/tree')
        .then((v) => {
            console.log(v)
            console.log(JSON.parse(v));
        })
        .catch((e) => console.error(e));
}

window.addEventListener('load', () => {
    load_tree()
});