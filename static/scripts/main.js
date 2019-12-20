new Vue ({
    el: "#wrapper",
    data: {
        info: "Email and password does not match.",

        signIn: {
            email: "",
            password: "",
        },
        forgotPass: {
            hidden: true,
            email: ""
        },
        register: {
            email: "",
            password: "",
            repeatPassword: ""
        }
    },
    methods: {
        submit_signIn () {
            /*
            let email = this.signIn.email;
            let password = this.signIn.password;

            axios.post("/signin", {email, password}).then(response => {
                console.log(response.data);
            });
            */
        },
        submit_forgotPass() {
            /*
            let email = this.forgotPass.email;
            let recaptchaValue = document.querySelector("#g-recaptcha-response").value;
            
            axios.post("/forgotpassword", {email}).then(response => {
                console.log(response.data);
            });
            */
        },
        submit_register () {
            /*
            let email = this.register.email;
            let password = this.register.password;
            let rpassword = this.register.repeatPassword;
            let recaptchaValue = document.querySelector("#g-recaptcha-response").value;

            axios.post("/register", {email, password, rpassword, recaptchaValue}).then(response => {
                console.log(response.data);
            });
            */
        },
        closeInfoMSG() {
            this.info = "";
        }
    }
})