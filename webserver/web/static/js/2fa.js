window.addEventListener('load', (e) => {
    const tokenInput = document.getElementById('tokeninput');

    if (tokenInput !== null && tokenInput !== undefined) {
        $('#enable2FAModal').on('show.bs.modal', () => {
            $.get('/profile/enable2fa').done(() => {
                $('#qrcodeimg').attr('src', '/profile/2faqr');
            })
        }).on('hide.bs.modal', () => {
            if (typeof $('#continueBtn').attr('disabled') == typeof undefined) {
                return location.reload();
            }
            $.get('/profile/remove2fa').done(() => {
                $('#qrcodeimg').attr('src', '/static/img/logo.svg');
            })
        });

        tokenInput.addEventListener('blur', (e) => {
            let token = tokenInput.value;

            $.post('/validatetotptoken', token, null, 'text')
                .done((a, content, somethingImportantIGuess) => {
                    let status = somethingImportantIGuess.status;

                    switch (status) {
                        case 200:
                            $('#continueBtn').removeAttr('disabled');
                            $(tokeninput).removeClass('is-invalid');
                            $(tokeninput).addClass('is-valid');
                            $(tokeninput).attr('disabled', 'true')
                            break;
                        case 204:
                            $('#continueBtn').attr('disabled', 'true');
                            $(tokeninput).removeClass('is-valid');
                            $(tokeninput).addClass('is-invalid');
                            break
                        default:
                            alert('There\'s been an error ?? !? !?? !??????? ');
                            return;
                    }
                }).fail(() => {
                    $('#continueBtn').attr('disabled', 'true')
                });

            tokenInput.classList.add('is-verefied');
        });
    }
});