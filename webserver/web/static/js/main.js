'use strict';

let flash_before_load = [];

/**
 * Puts up a flash message to screen
 * @param {string} msg 
 * @param {string} t 
 * @param {number} time 
 */
let flash = (msg, t, time = -1) => {
    console.log('Page is yet to be initiated');
    flash_before_load.push([msg, t, time]);
};

/**
 * Set cookie value
 * @param {string} name 
 * @param {*} value 
 * @param {number} days 
 */
function setCookie(name,value,days) {
    var expires = "";
    if (days) {
        var date = new Date();
        date.setTime(date.getTime() + (days*24*60*60*1000));
        expires = "; expires=" + date.toUTCString();
    }
    document.cookie = name + "=" + (value || "")  + expires + "; path=/";
}

/**
 * Returns cookie if set, otherwise returns null
 * @param {*} name Cookie's name
 * @returns {(string | null)} Cookie's value
 */
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


/**
 * Delete a cookie
 * @param {string} name Cookie name
 */
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

            // Set dark theme for all objects
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

    /**
     * Re-declaration
     * {@link flash}
     */
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

    // When window is loaded, the browser will cause the queued flashes
    // to pop up.
    flash_before_load.forEach((f) => {flash(f[0], f[1], f[2])});

    /**
     * To be honest, I have absolutly NO idea why I
     * put this section in scopes, probably was around
     * the time when I discovered that you can make scopes
     * like this.
     * 
     * Maybe so the code would not be editable trough console, but like...
     * ¯\_(ツ)_/¯
     */
    {
        const dropzone = document.getElementById('file-dropzone');
        const dropzoneModal = document.getElementById('dropzone-modal');

        if(dropzone != null) {

            /**
             * Function will prevent the default behavior of drag events
             * @param {*} e Event (I believe?)
             */
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
                    if(xhr.readyState === 4 && xhr.status === 201) console.log("Done!"); // 4 = done, 201 = HTTP Created
                    else if(xhr.readyState === 4 && xhr.status !== 201) console.error(e, xhr);
                });

                xhr.addEventListener("error", (e) => console.log(e))

                file.file((f) => { // Create file object
                    console.log(f, file)
                    formData.append('file', f, file.fullPath.substr(1)); // Append file to form data
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
                preventDefault(e); // To prevent default
                dropzoneModal.style.display = 'flex'; // To show dropzone modal
            }

            let onDragLeave = (e) => {
                preventDefault(e); // To prevent default
                dropzoneModal.style.display = 'none'; // To hide dropzone modal
            }

            dropzone.ondragenter = onDragOver;
            dropzone.ondragover = onDragOver;
            dropzone.ondragleave = onDragLeave;

            dropzone.ondrop = (e) => {
                onDragLeave(e);

                [...e.dataTransfer.items].forEach((item) => {  // Iterate over each item
                    item = item.webkitGetAsEntry();
                    console.log(item)
                    if(item.isFile) upload(item);
                    else if(item.isDirectory) uploadDir(item);
                });
            }
        }
    }
});