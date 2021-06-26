'use strict';

let flash_before_load = [];

let flash = (msg, t, time = -1) => {
    console.log('Page is yet to be initiated');
    flash_before_load.push([msg, t, time]);
};

function setCookie(name,value,days) {
    var expires = "";
    if (days) {
        var date = new Date();
        date.setTime(date.getTime() + (days*24*60*60*1000));
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + (value || "")  + expires + "; path=/";
}

function getCookie(name) {
    var nameEQ = name + "=";
    var ca = document.cookie.split(';');
    for(var i=0;i < ca.length;i++) {
        var c = ca[i];
        while (c.charAt(0)==' ') c = c.substring(1,c.length);
        if (c.indexOf(nameEQ) == 0) return c.substring(nameEQ.length,c.length);
    }
    return null;
}

function eraseCookie(name) {
    document.cookie = name +'=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
}

DarkReader.auto({
    brightness: 100,
    contrast: 100
})

var dmcookie = getCookie('darkmode');
if(!dmcookie || dmcookie === 'False') DarkReader.disable();

window.addEventListener('load', (e) => {
    const darkModeSwitch = document.getElementById('is-darkmode');

    if(darkModeSwitch !== null) {
        darkModeSwitch.addEventListener('change', (e) => {
            if(darkModeSwitch.checked) DarkReader.enable();
            else DarkReader.disable();

            setCookie('darkmode', DarkReader.isEnabled() ? 'True' : 'False', 365)

            const fsDarkModeQuery = document.querySelectorAll('.fs-darkmode');

            fsDarkModeQuery.forEach((obj) => {
                obj.style.filter = `invert(${DarkReader.isEnabled() ? '100%' : '0%'})`
            });

        });

        MEvent.addEventHandler('LocationChangeEvent', () => {
            const fsDarkModeQuery = document.querySelectorAll('.fs-darkmode');

            fsDarkModeQuery.forEach((obj) => {
                obj.style.filter = `invert(${DarkReader.isEnabled() ? '100%' : '0%'})`
            });
        });
    }

    const forms = document.querySelectorAll('.needs-validation');
    const flashContainer = document.getElementById('flashes-container');

    forms.forEach((form) => {
        form.addEventListener('submit', (event) => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });

    flash = (msg, t, time = -1) => {
        let div = document.createElement('div');
        div.classList.add('alert', `alert-${t}`, 'alert-dismissible', 'fade', 'show', 'm-4');
        div.innerHTML = `
            <p> ${msg} </p>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;

        flashContainer.appendChild(div);

        if(time > 0) setTimeout(()=>{ $(div).alert('close'); }, time)
    };

    flash_before_load.forEach((f) => {flash(f[0], f[1], f[2])});

    {
        const dropzone = document.getElementById('file-dropzone');
        const dropzoneModal = document.getElementById('dropzone-modal');

        if(dropzone != null) {

            let preventDefault = (e) => {
                e.preventDefault();
                e.stopPropagation();
            }

            let upload = (file) => {
                const url = '/upload';
                let formData = new FormData();
                let xhr = new XMLHttpRequest();
                xhr.open('POST', url, true);

                xhr.upload.addEventListener("progress", (e) => {
                    console.log(e, e.loaded * 100.0 / e.total)
                });

                xhr.addEventListener("readystatechange", (e) => {
                    if(xhr.readyState === 4 && xhr.status === 201) console.log("Done!");
                    else if(xhr.readyState === 4 && xhr.status !== 201) console.error(e, xhr);
                });

                xhr.addEventListener("error", (e) => console.log(e))

                file.file((f) => {
                    console.log(f, file)
                    formData.append('file', f, file.fullPath.substr(1));
                    xhr.send(formData);
                });

            }

            let uploadDir = (dir) => {
                let dirReader = dir.createReader();
                dirReader.readEntries((entries) => {
                    [...entries].forEach((entry) => {
                        if(entry.isFile) upload(entry);
                        else if(entry.isDirectory) uploadDir(entry);
                    });
                });
                // console.log(dirReader)
            }

            let onDragOver = (e) => {
                preventDefault(e);
                dropzoneModal.style.display = 'flex';
            }

            let onDragLeave = (e) => {
                preventDefault(e);
                dropzoneModal.style.display = 'none';
            }

            dropzone.ondragenter = onDragOver;
            dropzone.ondragover = onDragOver;
            dropzone.ondragleave = onDragLeave;

            dropzone.ondrop = (e) => {
                onDragLeave(e);

                [...e.dataTransfer.items].forEach((item) => {
                    item = item.webkitGetAsEntry();
                    console.log(item)
                    if(item.isFile) upload(item);
                    else if(item.isDirectory) uploadDir(item);
                });
            }
        }
    }
});