/* function validateName(name) {
    const re = /^([a-zA-Z ]){2,30}$/;
    return re.test(name);
}

function validateEmail(email) {
    const re = /\S+@\S+\.\S+/;
    return re.test(email);
}

function validatePassword(password) {
    return true;
}

function validateLoginForm() {
    const inputEmail = document.getElementById("email").value;
    return validateEmail(inputEmail);
}

function validateRegisterationForm() {
    const inputFullName = document.getElementById("name").value;
    const inputEmail = document.getElementById("email").value;
    const inputPassword = document.getElementById("password").value;

    return validateName(inputFullName) && validateEmail(inputEmail) && validatePassword(inputPassword);
} */

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
    });
});