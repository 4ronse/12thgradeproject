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

const getAllSelected = () => {
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

    return files;
}

const make_form = (data, content) => {
    console.assert(data.hasOwnProperty('action'), 'Action must be given');
    if(!data.hasOwnProperty('method')) data['method'] = 'POST';
    if(!data.hasOwnProperty('target')) data['target'] = '_blank';


    let form = document.createElement('form');
    form.action = data['action'];
    form.method = data['method'];
    form.target = data['target'];

    Object.entries(content).forEach(([k, v]) => {
        let hidden = document.createElement('input');
        hidden.type = 'hidden';
        hidden.name = k;
        hidden.value = v;
        form.appendChild(hidden);
    });

    return form;
}

const delete_files = () => {
    const files = getAllSelected();

    const form = make_form({'action': '/delete'}, {
        'files': files.join(';')
    });

    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);

    return files;
}

const download = () => {
    const files = getAllSelected();

    const form = make_form({'action': '/download'}, {
        'files': files.join(';')
    });

    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);

    return files;
}


window.addEventListener('load', () => {
    load_tree();

    let contextMenu = new ContextMenu();

    contextMenu.onmenu = (m, e) => {
        const selected = getAllSelected();

        if(selected.length === 0) {
            e.returnValue = true;
            return m.hide();
        }
    };

    contextMenu.addItem(new ContextMenuItem({
        text: 'Download',
        icon: {
            name: 'fa-download',
            style: 'fas'
        },
        onclick: download
    }));

    contextMenu.addItem(new ContextMenuItem({
        text: 'Delete',
        icon: {
            name: 'fa-trash-alt',
            style: 'fas'
        },
        onclick: delete_files
    }));

    contextMenu.import();
});
