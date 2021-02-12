window.addEventListener('load', () => {
    let ppinput = document.getElementById('profilepicinput');
    let ppimage = document.getElementById('profilepicimage');

    if (ppinput !== null || ppinput !== undefined) {
        let flag = true;

        ppinput.addEventListener('blur', () => {
            ppimage.src = ppinput.value
        });

        ppimage.addEventListener('load', () => {
            if (!flag) ppinput.classList.remove('is-invalid');
            flag = false;
        });

        ppimage.addEventListener('error', () => {
            flag = true;
            ppimage.src = '/defaultprofilepicture'
            ppinput.classList.add('is-invalid')
        });
    }
});