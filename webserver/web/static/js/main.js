let flash_before_load = [];

let flash = (msg, t, time = -1) => {
    console.log('Page is yet to be initiated');
    flash_before_load.push([msg, t, time]);
};

window.addEventListener('load', (e) => {
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
});