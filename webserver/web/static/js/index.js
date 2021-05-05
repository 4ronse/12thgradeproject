'use strict';

const FSLoadEvent = new MEvent('FSLoadEvent');
const LocationChangeEvent = new MEvent('LocationChangeEvent');
let tree = null;
let current = null;


function load_tree() {
    document.getElementById('loading-div').style.display = 'block';

    const container = document.getElementById('file-dropzone');
    container.innerHTML = '';

    $.get('/tree')
        .then((v) => {
            tree = makeFS(JSON.parse(v));
            current = tree;
            document.getElementById('loading-div').style.display = 'none';

            FSLoadEvent.dispatch(tree);
            LocationChangeEvent.dispatch(current);
        }).catch((e) => console.error(e));
}

window.addEventListener('load', () => {
    load_tree();
});

const singleClickHandler = (e) => {
    const target = e.currentTarget;

    if(e.ctrlKey) {
        if(target.classList.contains('selected')) target.classList.remove('selected');
        else target.classList.add('selected');
    } else {
        const allSelected = document.querySelectorAll('.selected');

        allSelected.forEach(selected => {
            selected.classList.remove('selected');
        });

        target.classList.add('selected');
    }
};

const doubleClickHandler = (e) => {
    e.preventDefault();
    const target = e.currentTarget;

    if (target.getAttribute('data-type') === 'file') {
        let link = document.createElement('a');
        link.download = target.getAttribute('data-name');
        link.href = `/download/${target.getAttribute('data-hashed-file-name')}`;
        link.click();
    } else if(target.getAttribute('data-type') === 'directory') {
        current = current.get(target.getAttribute('data-name'));
        LocationChangeEvent.dispatch(current);
    } else if(target.getAttribute('data-type') === 'parent') {
        current = current.parent;
        LocationChangeEvent.dispatch(current);
    }
}

LocationChangeEvent.addEventHandler((_tree) => {
    const container = document.getElementById('file-dropzone');
    container.innerHTML = '';

    if(_tree !== tree) {
        let parent = new Directory('../');
        let div = parent.getDiv();
        div.setAttribute('data-type', 'parent');

        container.appendChild(div);
        div.addEventListener('dblclick', doubleClickHandler);
        div.addEventListener('click', singleClickHandler);
    }

    _tree.children.forEach(child => {
        let div = child.getDiv();
        container.appendChild(div);

        div.addEventListener('dblclick', doubleClickHandler);
        div.addEventListener('click', singleClickHandler);
    });
});

const download = () => {
    const selected = document.querySelectorAll('.selected');
    let files = [];

    function getDirectoryFiles(loc) {
        let files = [];

        loc.children.forEach(child => {
            if(child.isFile) files.push(child.SHA256);
            else if(child.isDirectory) files = files.concat(getDirectoryFiles(child));
        });

        return files;
    }

    selected.forEach(selected => {
        if(selected.getAttribute('data-type') === 'file')
            files.push(selected.getAttribute('data-hashed-file-name'));
        else if(selected.getAttribute('data-type') === 'directory')
            files = files.concat(getDirectoryFiles(current.get(selected.getAttribute('data-name'))));
    });

    let form = document.createElement('form');
    form.action = '/download';
    form.method = 'post';
    form.target = '_blank';

    let hidden = document.createElement('input');
    hidden.type = 'hidden';
    hidden.name = 'files';
    hidden.value = files.join(';');

    form.appendChild(hidden);

    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);

    return files;
}
