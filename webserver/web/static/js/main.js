window.addEventListener('load', (e) => {
    const forms = document.querySelectorAll('.needs-validation');

    forms.forEach((form) => {
        form.addEventListener('submit', (event) => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);

        let ppinput = document.getElementById('profilepicinput');
        let ppimage = document.getElementById('profilepicimage');

        if (ppinput !== null || ppinput !== undefined) {
            let flag = true;

            ppinput.addEventListener('blur', (e) => {
                ppimage.src = ppinput.value
            });

            ppimage.addEventListener('load', (e) => {
                if (!flag) ppinput.classList.remove('is-invalid');
                flag = false;
            });

            ppimage.addEventListener('error', (e) => {
                flag = true;
                ppimage.src = '/defaultprofilepicture'
                ppinput.classList.add('is-invalid')
            });
        }
    });
});